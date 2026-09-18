<?php

namespace Pterodactyl\Http\Requests\Api\Client\Servers\Network;

use Illuminate\Validation\Rule;
use Pterodactyl\Models\Permission;
use Pterodactyl\Http\Requests\Api\Client\ClientApiRequest;

class PublishNoobtunnelRequest extends ClientApiRequest
{
    public function permission(): string
    {
        return Permission::ACTION_ALLOCATION_UPDATE;
    }

    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:191'],
            'protocol' => ['required', Rule::in(['tcp', 'udp', 'http', 'https'])],
            'public_port' => ['required', 'integer', 'between:1,65535'],
            'domain' => ['nullable', 'string', 'max:253', 'required_if:protocol,https'],
            'srv' => ['nullable', 'array'],
            'srv.service' => ['required_with:srv', 'string', 'max:63', 'regex:/^_?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/'],
            'srv.protocol' => ['required_with:srv', Rule::in(['tcp', 'udp'])],
            'srv.priority' => ['required_with:srv', 'integer', 'between:0,65535'],
            'srv.weight' => ['required_with:srv', 'integer', 'between:0,65535'],
        ];
    }
}
