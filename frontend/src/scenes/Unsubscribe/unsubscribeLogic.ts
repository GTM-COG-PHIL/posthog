import { actions, afterMount, kea, path } from 'kea'
import { loaders } from 'kea-loaders'

import api from 'lib/api'

import type { unsubscribeLogicType } from './unsubscribeLogicType'

export const unsubscribeLogic = kea<unsubscribeLogicType>([
    path(['scenes', 'Unsubscribe', 'unsubscribeLogic']),
    actions({
        attemptUnsubscribe: (token: string) => ({ token }),
    }),

    loaders(() => ({
        unsubscription: {
            __default: null as boolean | null,
            attemptUnsubscribe: async ({ token }) => {
                const res = await api.create(`api/unsubscribe`, { token })
                return res.success
            },
        },
    })),
    afterMount(({ actions }) => {
        const hash = window.location.hash
        const params = new URLSearchParams(hash.slice(1))
        const token = params.get('token')
        if (token) {
            actions.attemptUnsubscribe(token)
        }
    }),
])
