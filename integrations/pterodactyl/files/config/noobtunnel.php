<?php

return [
    'url' => rtrim((string) env('NOOBTUNNEL_URL', ''), '/'),
    'token' => (string) env('NOOBTUNNEL_TOKEN', ''),
    // Comma-separated Pterodactyl node ID to Noobtunnel agent ID mappings,
    // for example: 1:2,3:5.
    'node_agents' => (string) env('NOOBTUNNEL_NODE_AGENTS', ''),
    'exit_node_id' => (string) env('NOOBTUNNEL_EXIT_NODE_ID', ''),
];
