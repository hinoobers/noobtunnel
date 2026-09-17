import React, { useEffect, useMemo, useState } from 'react';
import tw from 'twin.macro';
import Modal from '@/components/elements/Modal';
import Input from '@/components/elements/Input';
import Select from '@/components/elements/Select';
import { Button } from '@/components/elements/button';
import { useFlashKey } from '@/plugins/useFlash';
import {
    getNoobtunnelPublications,
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

const NoobtunnelPublishButton = ({ uuid, allocationId, allocationPort, serverName }: Props) => {
    const [visible, setVisible] = useState(false);
    const [loading, setLoading] = useState(false);
    const [loaded, setLoaded] = useState(false);
    const [dirty, setDirty] = useState(false);
    const [publications, setPublications] = useState<NoobtunnelPublication[]>([]);
    const [protocol, setProtocol] = useState<NoobtunnelProtocol>('tcp');
    const [name, setName] = useState(`${serverName} ${allocationPort}`);
    const [publicPort, setPublicPort] = useState(allocationPort);
    const [domain, setDomain] = useState('');
    const { clearFlashes, clearAndAddHttpError } = useFlashKey('server:network');

    const current = useMemo(
        () => publications.find((publication) => publication.protocol === protocol),
        [publications, protocol]
    );

    useEffect(() => {
        getNoobtunnelPublications(uuid, allocationId)
            .then(setPublications)
            .catch(clearAndAddHttpError)
            .then(() => setLoaded(true));
    }, [uuid, allocationId]);

    useEffect(() => {
        const publication = publications.find((item) => item.protocol === protocol);
        setName(publication?.name || `${serverName} ${allocationPort} ${protocol.toUpperCase()}`);
        setPublicPort(publication?.publicPort || (protocol === 'https' ? 443 : allocationPort));
        setDomain(publication?.domain || '');
        setDirty(false);
    }, [protocol, publications, serverName, allocationPort]);

    const save = async () => {
        clearFlashes();
        setLoading(true);
        try {
            const publication = await publishWithNoobtunnel(uuid, allocationId, {
                name,
                protocol,
                publicPort,
                domain,
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
                    {(protocol === 'http' || protocol === 'https') && (
                        <label css={tw`block text-sm text-neutral-200 sm:col-span-2`}>
                            <span css={tw`block mb-2`}>Domain {protocol === 'https' ? '(required)' : '(optional)'}</span>
                            <Input
                                value={domain}
                                placeholder={'game.example.com'}
                                onChange={(event) => {
                                    setDomain(event.currentTarget.value);
                                    setDirty(true);
                                }}
                            />
                        </label>
                    )}
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
                    <Button type={'button'} onClick={save} disabled={loading || !name || (protocol === 'https' && !domain)}>
                        {current ? 'Update publication' : `Publish ${protocol.toUpperCase()}`}
                    </Button>
                </div>
            </Modal>
        </>
    );
};

export default NoobtunnelPublishButton;
