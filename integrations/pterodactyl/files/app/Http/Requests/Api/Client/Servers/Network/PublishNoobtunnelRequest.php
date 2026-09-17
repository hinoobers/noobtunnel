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
        ];
    }
}
