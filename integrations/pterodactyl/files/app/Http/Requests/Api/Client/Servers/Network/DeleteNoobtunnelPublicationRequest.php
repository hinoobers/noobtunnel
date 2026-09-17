<?php

namespace Pterodactyl\Http\Requests\Api\Client\Servers\Network;

use Illuminate\Validation\Rule;
use Pterodactyl\Models\Permission;
use Pterodactyl\Http\Requests\Api\Client\ClientApiRequest;

class DeleteNoobtunnelPublicationRequest extends ClientApiRequest
{
    public function permission(): string
    {
        return Permission::ACTION_ALLOCATION_UPDATE;
    }

    public function rules(): array
    {
        return ['protocol' => ['required', Rule::in(['tcp', 'udp', 'http', 'https'])]];
    }
}
