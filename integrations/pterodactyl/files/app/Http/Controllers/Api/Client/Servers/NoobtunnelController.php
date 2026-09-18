<?php

namespace Pterodactyl\Http\Controllers\Api\Client\Servers;

use Throwable;
use Pterodactyl\Models\Server;
use Illuminate\Http\JsonResponse;
use Pterodactyl\Facades\Activity;
use Pterodactyl\Models\Allocation;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Http\Client\PendingRequest;
use Pterodactyl\Exceptions\DisplayException;
use Pterodactyl\Http\Controllers\Api\Client\ClientApiController;
use Pterodactyl\Http\Requests\Api\Client\Servers\Network\GetNoobtunnelPublicationRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Network\PublishNoobtunnelRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Network\DeleteNoobtunnelPublicationRequest;

class NoobtunnelController extends ClientApiController
{
    public function index(
        GetNoobtunnelPublicationRequest $request,
        Server $server,
        Allocation $allocation,
    ): JsonResponse {
        $this->assertAllocation($server, $allocation);

        $storedRows = DB::table('noobtunnel_publications')
            ->where('server_id', $server->id)
            ->where('allocation_id', $allocation->id)
            ->orderBy('protocol')
            ->get();

        try {
            $response = $this->client()->get('/api/resources');
        } catch (Throwable $exception) {
            throw new DisplayException('Could not reach Noobtunnel: ' . $exception->getMessage());
        }
        if (!$response->successful()) {
            throw new DisplayException('Noobtunnel could not list the available domains.');
        }
        $resources = collect($response->json('resources') ?: [])->keyBy(fn ($resource) => (int) ($resource['id'] ?? 0));
        $rows = $storedRows->map(fn ($row) => $this->publication($row, $resources->get((int) $row->resource_id)));
        $domains = collect($response->json('domains') ?: [])->map(fn ($domain) => [
            'hostname' => $domain['hostname'],
            'pattern' => $domain['pattern'] ?? $domain['hostname'],
            'kind' => ($domain['kind'] ?? 'direct') === 'wildcard' ? 'wildcard' : 'direct',
            'automatic' => !empty($domain['providerId']),
        ])->values();

        return new JsonResponse([
            'publications' => $rows,
            'domains' => $domains,
            'suggestedSrv' => $this->suggestedSrv($server),
        ]);
    }

    public function publish(
        PublishNoobtunnelRequest $request,
        Server $server,
        Allocation $allocation,
    ): JsonResponse {
        $this->assertAllocation($server, $allocation);
        $data = $request->validated();
        $protocol = strtolower($data['protocol']);
        $domain = strtolower(trim((string) ($data['domain'] ?? '')));
        $existing = DB::table('noobtunnel_publications')
            ->where('allocation_id', $allocation->id)
            ->where('protocol', $protocol)
            ->first();

        $payload = [
            'name' => trim($data['name']),
            'protocol' => $protocol,
            'targets' => [[
                'agentId' => $this->agentId($server->node_id),
                'host' => $this->targetHost($allocation->ip),
                'port' => (int) $allocation->port,
                'enabled' => true,
            ]],
            'strategy' => 'round-robin',
            'exitNodeId' => config('noobtunnel.exit_node_id', ''),
            'listenPort' => (int) $data['public_port'],
            'domain' => $domain,
            'srv' => $data['srv'] ?? null,
            'enabled' => true,
            'proxyProtocol' => '',
            'rules' => [],
            'identity' => false,
            'blockExploits' => false,
            'blockHighRiskIps' => false,
            'websockets' => true,
        ];

        try {
            $response = $existing
                ? $this->client()->patch('/api/resources/' . $existing->resource_id, $payload)
                : $this->client()->post('/api/resources', $payload);
        } catch (Throwable $exception) {
            throw new DisplayException('Could not reach Noobtunnel: ' . $exception->getMessage());
        }

        if (!$response->successful()) {
            $detail = $response->json('error') ?: $response->json('message') ?: ('HTTP ' . $response->status());
            throw new DisplayException('Noobtunnel rejected the publication: ' . $detail);
        }

        $resource = $response->json('resource');
        if (!is_array($resource) || empty($resource['id'])) {
            throw new DisplayException('Noobtunnel returned an invalid resource response.');
        }

        DB::table('noobtunnel_publications')->updateOrInsert(
            ['allocation_id' => $allocation->id, 'protocol' => $protocol],
            [
                'server_id' => $server->id,
                'resource_id' => (int) $resource['id'],
                'name' => $payload['name'],
                'public_port' => (int) $data['public_port'],
                'domain' => $domain ?: null,
                'public_address' => $resource['public'] ?? null,
                'created_at' => $existing->created_at ?? now(),
                'updated_at' => now(),
            ],
        );

        Activity::event('server:allocation.noobtunnel.publish')
            ->subject($allocation)
            ->property(['protocol' => $protocol, 'resource_id' => $resource['id'], 'public' => $resource['public'] ?? null])
            ->log();

        $row = DB::table('noobtunnel_publications')
            ->where('allocation_id', $allocation->id)
            ->where('protocol', $protocol)
            ->first();

        return new JsonResponse(['publication' => $this->publication($row, $resource)]);
    }

    public function delete(
        DeleteNoobtunnelPublicationRequest $request,
        Server $server,
        Allocation $allocation,
    ): JsonResponse {
        $this->assertAllocation($server, $allocation);
        $protocol = strtolower($request->validated('protocol'));
        $row = DB::table('noobtunnel_publications')
            ->where('allocation_id', $allocation->id)
            ->where('protocol', $protocol)
            ->first();
        if (!$row) {
            return new JsonResponse([], JsonResponse::HTTP_NO_CONTENT);
        }

        try {
            $response = $this->client()->delete('/api/resources/' . $row->resource_id);
        } catch (Throwable $exception) {
            throw new DisplayException('Could not reach Noobtunnel: ' . $exception->getMessage());
        }
        if (!$response->successful() && $response->status() !== 404) {
            $detail = $response->json('error') ?: $response->json('message') ?: ('HTTP ' . $response->status());
            throw new DisplayException('Noobtunnel rejected the removal: ' . $detail);
        }

        DB::table('noobtunnel_publications')->where('id', $row->id)->delete();
        Activity::event('server:allocation.noobtunnel.remove')
            ->subject($allocation)
            ->property(['protocol' => $protocol, 'resource_id' => $row->resource_id])
            ->log();

        return new JsonResponse([], JsonResponse::HTTP_NO_CONTENT);
    }

    private function client(): PendingRequest
    {
        $url = config('noobtunnel.url');
        $token = config('noobtunnel.token');
        if (!$url || !$token) {
            throw new DisplayException('Noobtunnel is not configured on this Panel.');
        }

        return Http::baseUrl($url)->withToken($token)->acceptJson()->asJson()->connectTimeout(5)->timeout(15);
    }

    private function agentId(int $nodeId): int
    {
        foreach (explode(',', (string) config('noobtunnel.node_agents')) as $mapping) {
            [$node, $agent] = array_pad(explode(':', trim($mapping), 2), 2, null);
            if ((int) $node === $nodeId && (int) $agent > 0) {
                return (int) $agent;
            }
        }

        throw new DisplayException("Pterodactyl node {$nodeId} is not mapped to a Noobtunnel agent.");
    }

    private function targetHost(string $ip): string
    {
        $ip = trim($ip, '[] ');
        if ($ip === '' || $ip === '0.0.0.0' || $ip === '::' || $ip === '::1' || str_starts_with($ip, '127.')) {
            return 'pterodactyl';
        }

        return $ip;
    }

    private function assertAllocation(Server $server, Allocation $allocation): void
    {
        if ((int) $allocation->server_id !== (int) $server->id) {
            abort(404);
        }
    }

    private function publication(object $row, ?array $resource = null): array
    {
        return [
            'resourceId' => (int) $row->resource_id,
            'protocol' => $row->protocol,
            'name' => $row->name,
            'publicPort' => (int) $row->public_port,
            'domain' => $row->domain,
            'publicAddress' => $row->public_address,
            'srv' => $resource['srv'] ?? null,
        ];
    }

    private function suggestedSrv(Server $server): ?array
    {
        $egg = strtolower((string) optional($server->egg)->name);
        $nest = strtolower((string) optional($server->nest)->name);
        $image = strtolower((string) $server->image);
        $startup = strtolower((string) $server->startup);
        $description = implode(' ', [$egg, $nest, $image, $startup]);

        $presets = [
            ['needles' => ['minecraft', 'paper', 'purpur', 'spigot', 'bungeecord', 'velocity'], 'service' => 'minecraft', 'protocol' => 'tcp', 'label' => 'Minecraft Java'],
            ['needles' => ['mumble', 'murmur'], 'service' => 'mumble', 'protocol' => 'tcp', 'label' => 'Mumble'],
            ['needles' => ['teamspeak'], 'service' => 'ts3', 'protocol' => 'udp', 'label' => 'TeamSpeak 3'],
        ];
        foreach ($presets as $preset) {
            foreach ($preset['needles'] as $needle) {
                if (str_contains($description, $needle)) {
                    unset($preset['needles']);

                    return $preset + ['priority' => 0, 'weight' => 0];
                }
            }
        }

        return null;
    }
}
