import { Client } from 'pg'
import { hash } from './utils'

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
			await env.AUTH_TOKENS.delete(hashedToken)
		} catch (e) {
			console.log('delete token error:', e)
			return new Response('Cloudflare KV Error, please try again...', { status: 500 })
		}

		// TODO: deprecated store token in hyperdrive
		try {
			const client = new Client({ connectionString: env.HYPERDRIVE.connectionString })
			await client.connect()

			await client.query(`
                delete
                from user_tokens
                where token = $1
			`, [hashedToken])
		} catch (e) {
			console.log('delete token error:', e)
			return new Response('Cloudflare Hyperdrive Error, please try again...', { status: 500 })
		}
	}

	return Response.redirect(callback, 302)
}
