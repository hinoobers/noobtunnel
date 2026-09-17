<?php

declare(strict_types=1);

$mode = $argv[1] ?? '';
$panel = rtrim($argv[2] ?? '/var/www/pterodactyl', '/');
if (!in_array($mode, ['install', 'uninstall'], true) || !is_file("{$panel}/artisan")) {
    fwrite(STDERR, "usage: php patch.php install|uninstall /path/to/pterodactyl\n");
    exit(2);
}

$routeFile = "{$panel}/routes/api-client.php";
$allocationFile = "{$panel}/resources/scripts/components/server/network/AllocationRow.tsx";
$sourceRoot = __DIR__ . '/files';

$routeBlock = <<<'PHP'
        // noobtunnel:begin
        Route::get('/allocations/{allocation}/noobtunnel', [Client\Servers\NoobtunnelController::class, 'index']);
        Route::post('/allocations/{allocation}/noobtunnel', [Client\Servers\NoobtunnelController::class, 'publish']);
        Route::delete('/allocations/{allocation}/noobtunnel', [Client\Servers\NoobtunnelController::class, 'delete']);
        // noobtunnel:end
PHP;

$componentImport = "import NoobtunnelPublishButton from '@/components/server/network/NoobtunnelPublishButton'; // noobtunnel\n";
$componentState = "    const serverName = ServerContext.useStoreState((state) => state.server.data!.name); // noobtunnel\n";
$componentButton = <<<'TSX'
                {/* noobtunnel:begin */}
                <Can action={'allocation.update'}>
                    <NoobtunnelPublishButton
                        uuid={uuid}
                        allocationId={allocation.id}
                        allocationPort={allocation.port}
                        serverName={serverName}
                    />
                </Can>
                {/* noobtunnel:end */}
TSX;

function replaceOnce(string $path, string $needle, string $replacement): void
{
    $contents = file_get_contents($path);
    $position = $contents === false ? false : strpos($contents, $needle);
    if ($position === false) {
        throw new RuntimeException("could not find patch anchor in {$path}");
    }
    $updated = substr_replace($contents, $replacement, $position, strlen($needle));
    if (file_put_contents($path, $updated) === false) {
        throw new RuntimeException("could not patch {$path}");
    }
}

function copyTree(string $source, string $destination): void
{
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST,
    );
    foreach ($iterator as $item) {
        $relative = substr($item->getPathname(), strlen($source) + 1);
        $target = $destination . '/' . $relative;
        if ($item->isDir()) {
            if (!is_dir($target) && !mkdir($target, 0755, true) && !is_dir($target)) {
                throw new RuntimeException("could not create {$target}");
            }
        } else {
            if (!is_dir(dirname($target))) {
                mkdir(dirname($target), 0755, true);
            }
            if (!copy($item->getPathname(), $target)) {
                throw new RuntimeException("could not copy {$target}");
            }
        }
    }
}

function removeTreeFiles(string $source, string $destination): void
{
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS),
    );
    foreach ($iterator as $item) {
        if ($item->isFile()) {
            $relative = substr($item->getPathname(), strlen($source) + 1);
            @unlink($destination . '/' . $relative);
        }
    }
}

if ($mode === 'install') {
    copyTree($sourceRoot, $panel);

    $routes = file_get_contents($routeFile);
    if (!str_contains($routes, '// noobtunnel:begin')) {
        $anchor = "        Route::delete('/allocations/{allocation}', [Client\\Servers\\NetworkAllocationController::class, 'delete']);";
        replaceOnce($routeFile, $anchor, $anchor . "\n" . $routeBlock);
    }

    $component = file_get_contents($allocationFile);
    if (!str_contains($component, "NoobtunnelPublishButton from")) {
        $anchor = "import getServerAllocations from '@/api/swr/getServerAllocations';\n";
        replaceOnce($allocationFile, $anchor, $anchor . $componentImport);
    }
    $component = file_get_contents($allocationFile);
    if (!str_contains($component, 'const serverName = ServerContext')) {
        $anchor = "    const uuid = ServerContext.useStoreState((state) => state.server.data!.uuid);\n";
        replaceOnce($allocationFile, $anchor, $anchor . $componentState);
    }
    $component = file_get_contents($allocationFile);
    if (!str_contains($component, '{/* noobtunnel:begin */}')) {
        $anchor = "            <div className={'flex justify-end space-x-4 mt-4 w-full md:mt-0 md:w-48'}>\n";
        $replacement = "            <div className={'flex justify-end space-x-4 mt-4 w-full md:mt-0 md:w-auto'}>\n" . $componentButton . "\n";
        replaceOnce($allocationFile, $anchor, $replacement);
    }
    echo "Noobtunnel Panel integration patched.\n";
    exit(0);
}

$routes = file_get_contents($routeFile);
$routes = preg_replace('/\n\s*\/\/ noobtunnel:begin.*?\/\/ noobtunnel:end/s', '', $routes);
file_put_contents($routeFile, $routes);

$component = file_get_contents($allocationFile);
$component = str_replace($componentImport, '', $component);
$component = str_replace($componentState, '', $component);
$component = preg_replace('/\n\s*\{\/\* noobtunnel:begin \*\/\}.*?\{\/\* noobtunnel:end \*\/\}/s', '', $component);
$component = str_replace("md:w-auto'}>\n                {allocation.isDefault", "md:w-48'}>\n                {allocation.isDefault", $component);
file_put_contents($allocationFile, $component);
removeTreeFiles($sourceRoot, $panel);
echo "Noobtunnel Panel integration unpatched; its database records were preserved.\n";
