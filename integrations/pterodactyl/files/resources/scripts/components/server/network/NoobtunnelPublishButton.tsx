import React, { useEffect, useMemo, useState } from 'react';
import tw from 'twin.macro';
import Modal from '@/components/elements/Modal';
import Input from '@/components/elements/Input';
import Select from '@/components/elements/Select';
import { Button } from '@/components/elements/button';
import { useFlashKey } from '@/plugins/useFlash';
import {
    getNoobtunnelPublications,
    NoobtunnelDomain,
    NoobtunnelProtocol,
    NoobtunnelPublication,
    publishWithNoobtunnel,
    unpublishFromNoobtunnel,
} from '@/api/server/network/noobtunnel';

interface Props {
    uuid: string;
    allocationId: number;
    allocationPort: number;
    serverName: string;
}

const protocols: NoobtunnelProtocol[] = ['tcp', 'udp', 'http', 'https'];
const slugify = (value: string) =>
    value
        .toLowerCase()
        .trim()
        .replace(/[^a-z0-9-]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .replace(/-{2,}/g, '-')
        .slice(0, 40);

const NoobtunnelPublishButton = ({ uuid, allocationId, allocationPort, serverName }: Props) => {
    const [visible, setVisible] = useState(false);
    const [loading, setLoading] = useState(false);
    const [loaded, setLoaded] = useState(false);
    const [dirty, setDirty] = useState(false);
    const [publications, setPublications] = useState<NoobtunnelPublication[]>([]);
    const [domains, setDomains] = useState<NoobtunnelDomain[]>([]);
    const [protocol, setProtocol] = useState<NoobtunnelProtocol>('tcp');
    const [name, setName] = useState(`${serverName} ${allocationPort}`);
    const [publicPort, setPublicPort] = useState(allocationPort);
    const [domainChoice, setDomainChoice] = useState('');
    const [subdomain, setSubdomain] = useState(slugify(serverName));
    const { clearFlashes, clearAndAddHttpError } = useFlashKey('server:network');

    const current = useMemo(
        () => publications.find((publication) => publication.protocol === protocol),
        [publications, protocol]
    );
    const selectedDomain = useMemo(
        () => domains.find((domain) => domain.hostname === domainChoice),
        [domains, domainChoice]
    );
    const resolvedDomain = useMemo(() => {
        if (!selectedDomain) return '';
        if (selectedDomain.kind !== 'wildcard') return selectedDomain.hostname;
        const label = slugify(subdomain);
        return label ? `${label}.${selectedDomain.hostname}` : '';
    }, [selectedDomain, subdomain]);

    useEffect(() => {
        getNoobtunnelPublications(uuid, allocationId)
            .then((options) => {
                setPublications(options.publications);
                setDomains(options.domains);
            })
            .catch(clearAndAddHttpError)
            .then(() => setLoaded(true));
    }, [uuid, allocationId]);

    useEffect(() => {
        const publication = publications.find((item) => item.protocol === protocol);
        setName(publication?.name || `${serverName} ${allocationPort} ${protocol.toUpperCase()}`);
        setPublicPort(publication?.publicPort || (protocol === 'https' ? 443 : allocationPort));
        const publishedDomain = publication?.domain || '';
        const matching = domains.find(
            (item) =>
                (item.kind === 'direct' && item.hostname === publishedDomain) ||
                (item.kind === 'wildcard' && publishedDomain.endsWith(`.${item.hostname}`))
        );
        const choice = matching || domains[0];
        setDomainChoice(choice?.hostname || '');
        setSubdomain(
            matching?.kind === 'wildcard'
                ? publishedDomain.slice(0, -(matching.hostname.length + 1))
                : slugify(serverName)
        );
        setDirty(false);
    }, [protocol, publications, domains, serverName, allocationPort]);

    const save = async () => {
        clearFlashes();
        setLoading(true);
        try {
            const publication = await publishWithNoobtunnel(uuid, allocationId, {
                name,
                protocol,
                publicPort,
                domain: protocol === 'http' || protocol === 'https' ? resolvedDomain : '',
            });
            setPublications((items) => items.filter((item) => item.protocol !== protocol).concat(publication));
            setDirty(false);
        } catch (error: any) {
            clearAndAddHttpError(error);
        } finally {
            setLoading(false);
        }
    };

    const remove = async () => {
        clearFlashes();
        setLoading(true);
        try {
            await unpublishFromNoobtunnel(uuid, allocationId, protocol);
            setPublications((items) => items.filter((item) => item.protocol !== protocol));
            setDirty(false);
        } catch (error: any) {
            clearAndAddHttpError(error);
        } finally {
            setLoading(false);
        }
    };

    return (
        <>
            <Button.Text
                size={Button.Sizes.Small}
                disabled={!loaded}
                onClick={() => setVisible(true)}
                title={'Publish this private allocation through Noobtunnel'}
            >
                {publications.length ? `Published (${publications.length})` : 'Publish'}
            </Button.Text>
            <Modal
                visible={visible}
                onDismissed={() => setVisible(false)}
                closeOnBackground={!dirty}
                closeOnEscape={!dirty}
                showSpinnerOverlay={loading}
            >
                <h2 css={tw`text-2xl text-neutral-100 mb-2`}>Publish with Noobtunnel</h2>
                <p css={tw`text-sm text-neutral-300 mb-6`}>
                    The agent connects to this allocation on the node itself. No public Wings port or container IP is
                    needed.
                </p>
                <div css={tw`grid grid-cols-1 sm:grid-cols-2 gap-4`}>
                    <label css={tw`block text-sm text-neutral-200`}>
                        <span css={tw`block mb-2`}>Protocol</span>
                        <Select
                            value={protocol}
                            onChange={(event) => setProtocol(event.currentTarget.value as NoobtunnelProtocol)}
                        >
                            {protocols.map((value) => (
                                <option key={value} value={value}>
                                    {value.toUpperCase()}
                                </option>
                            ))}
                        </Select>
                    </label>
                    <label css={tw`block text-sm text-neutral-200`}>
                        <span css={tw`block mb-2`}>Public port</span>
                        <Input
                            type={'number'}
                            min={1}
                            max={65535}
                            value={publicPort}
                            disabled={protocol === 'https'}
                            onChange={(event) => {
                                setPublicPort(Number(event.currentTarget.value));
                                setDirty(true);
                            }}
                        />
                    </label>
                    <label css={tw`block text-sm text-neutral-200 sm:col-span-2`}>
                        <span css={tw`block mb-2`}>Resource name</span>
                        <Input
                            value={name}
                            onChange={(event) => {
                                setName(event.currentTarget.value);
                                setDirty(true);
                            }}
                        />
                    </label>
                    {(protocol === 'http' || protocol === 'https') &&
                        (domains.length ? (
                            <>
                                {selectedDomain?.kind === 'wildcard' && (
                                    <label css={tw`block text-sm text-neutral-200`}>
                                        <span css={tw`block mb-2`}>Subdomain</span>
                                        <Input
                                            value={subdomain}
                                            placeholder={'game'}
                                            onChange={(event) => {
                                                setSubdomain(event.currentTarget.value);
                                                setDirty(true);
                                            }}
                                        />
                                    </label>
                                )}
                                <label
                                    css={[
                                        tw`block text-sm text-neutral-200`,
                                        selectedDomain?.kind !== 'wildcard' && tw`sm:col-span-2`,
                                    ]}
                                >
                                    <span css={tw`block mb-2`}>Domain</span>
                                    <Select
                                        value={domainChoice}
                                        onChange={(event) => {
                                            setDomainChoice(event.currentTarget.value);
                                            setDirty(true);
                                        }}
                                    >
                                        {domains.map((item) => (
                                            <option key={`${item.kind}:${item.hostname}`} value={item.hostname}>
                                                {item.kind === 'wildcard' ? item.pattern : item.hostname}
                                            </option>
                                        ))}
                                    </Select>
                                </label>
                                <p css={tw`text-xs text-neutral-400 sm:col-span-2`}>
                                    Publishes as {resolvedDomain || '—'}. Domains are managed in Noobtunnel.
                                </p>
                            </>
                        ) : (
                            <p css={tw`text-sm text-red-300 sm:col-span-2`}>
                                No existing Noobtunnel domain is available. Add one in Noobtunnel first.
                            </p>
                        ))}
                </div>
                {current?.publicAddress && (
                    <p css={tw`mt-4 text-sm text-green-300 break-all`}>Live at {current.publicAddress}</p>
                )}
                <div css={tw`mt-8 flex flex-wrap justify-end gap-3`}>
                    {current && (
                        <Button.Danger type={'button'} onClick={remove} disabled={loading}>
                            Unpublish {protocol.toUpperCase()}
                        </Button.Danger>
                    )}
                    <Button
                        type={'button'}
                        onClick={save}
                        disabled={
                            loading ||
                            !name ||
                            ((protocol === 'http' || protocol === 'https') && !resolvedDomain)
                        }
                    >
                        {current ? 'Update publication' : `Publish ${protocol.toUpperCase()}`}
                    </Button>
                </div>
            </Modal>
        </>
    );
};

export default NoobtunnelPublishButton;
