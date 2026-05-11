import { useValues } from 'kea'

import { BridgePage } from 'lib/components/BridgePage/BridgePage'
import { SpinnerOverlay } from 'lib/lemon-ui/Spinner/Spinner'
import { SceneExport } from 'scenes/sceneTypes'

import { unsubscribeLogic } from './unsubscribeLogic'

export const scene: SceneExport = {
    component: Unsubscribe,
    logic: unsubscribeLogic,
}

export function Unsubscribe(): JSX.Element {
    const { unsubscriptionLoading, unsubscription } = useValues(unsubscribeLogic)
    return (
        <BridgePage view="unsubscribe">
            {unsubscriptionLoading ? (
                <SpinnerOverlay sceneLevel />
            ) : unsubscription === true ? (
                <div>
                    <h2>You have been unsubscribed!</h2>
                    <p>You will no longer receive these kinds of emails.</p>
                </div>
            ) : unsubscription === false ? (
                <div>
                    <h2>Something went wrong!</h2>
                    <p>Your may already be unsubscribed or the link you clicked may be invalid.</p>
                </div>
            ) : (
                <div>
                    <h2>Invalid unsubscribe link</h2>
                    <p>The link you clicked appears to be invalid or incomplete. Please try clicking the link from your email again.</p>
                </div>
            )}
        </BridgePage>
    )
}

export default Unsubscribe
