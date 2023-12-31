import { Client } from 'pg'
import { hash, trackLatency } from './utils'

const landing = 'https://www.deploys.app/'

/**
 * @param {import('@cloudflare/workers-types').Request} request
 * @param {Env} env
 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
 * @returns {Promise<import('@cloudflare/workers-types').Response>}
 **/
export default async function (request, env, ctx) {
	const url = new URL(request.url)
	const token = url.searchParams.get('token')
	const callback = url.searchParams.get('callback') || landing

	if (token) {
		const hashedToken = await hash(token)

		try {
			const client = new Client({ connectionString: env.HYPERDRIVE.connectionString })
			await client.connect()
			await trackLatency(request, env, 'delete_token', () =>
				client.query('delete from user_tokens where token = $1', [hashedToken]))
		} catch (e) {
			console.log('delete token error:', e)
			return new Response('Database error, please try again...', { status: 500 })
		}
	}

	return Response.redirect(callback, 302)
}
