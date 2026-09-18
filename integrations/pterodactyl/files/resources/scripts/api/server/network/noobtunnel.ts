import http from '@/api/http';

export type NoobtunnelProtocol = 'tcp' | 'udp' | 'http' | 'https';

export interface NoobtunnelPublication {
    resourceId: number;
    protocol: NoobtunnelProtocol;
    name: string;
    publicPort: number;
    domain: string | null;
    publicAddress: string | null;
}

export interface NoobtunnelDomain {
    hostname: string;
    pattern: string;
    kind: 'direct' | 'wildcard';
}

export interface NoobtunnelOptions {
    publications: NoobtunnelPublication[];
    domains: NoobtunnelDomain[];
}

const endpoint = (uuid: string, allocationId: number) =>
    `/api/client/servers/${uuid}/network/allocations/${allocationId}/noobtunnel`;

export const getNoobtunnelPublications = async (
    uuid: string,
    allocationId: number
): Promise<NoobtunnelOptions> => {
    const { data } = await http.get(endpoint(uuid, allocationId));
    return { publications: data.publications || [], domains: data.domains || [] };
};

export const publishWithNoobtunnel = async (
    uuid: string,
    allocationId: number,
    body: { name: string; protocol: NoobtunnelProtocol; publicPort: number; domain: string }
): Promise<NoobtunnelPublication> => {
    const { data } = await http.post(endpoint(uuid, allocationId), {
        name: body.name,
        protocol: body.protocol,
        public_port: body.publicPort,
        domain: body.domain,
    });
    return data.publication;
};

export const unpublishFromNoobtunnel = async (
    uuid: string,
    allocationId: number,
    protocol: NoobtunnelProtocol
): Promise<void> => {
    await http.delete(endpoint(uuid, allocationId), { data: { protocol } });
};
