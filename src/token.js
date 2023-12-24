import { Client } from 'pg'
import * as utils from './utils'

/**
 * @param {import('@cloudflare/workers-types').Request} request
 * @param {Env} env
 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
 * @returns {Promise<import('@cloudflare/workers-types').Response>}
 **/
export default async function (request, env, ctx) {
	if (request.method !== 'POST') {
		return new Response('Method not allowed', { status: 405 })
	}

	const f = await request.formData()
	const clientId = f.get('client_id')
	if (!clientId) {
		return new Response('Missing client_id parameter', { status: 400 })
	}
	const clientSecret = f.get('client_secret')
	if (!clientSecret) {
		return new Response('Missing client_secret parameter', { status: 400 })
	}
	const code = f.get('code') || ''
	if (!code) {
		return new Response('Missing code parameter', { status: 400 })
	}

	const oauth2Client = await utils.getOAuth2Client(env, ctx, clientId)
	if (!oauth2Client) {
		return new Response('Invalid client_id parameter', { status: 400 })
	}
	if (clientSecret !== oauth2Client.secret) {
		return new Response('Invalid client_secret parameter', { status: 400 })
	}

	const email = await utils.getOAuth2EmailFromCode(request, env, oauth2Client.id, code)
	if (!email) {
		return new Response('Invalid code parameter', { status: 400 })
	}

	const token = utils.generateToken()
	const hashedToken = await utils.hash(token)
	try {
		const client = new Client({ connectionString: env.HYPERDRIVE.connectionString })
		await client.connect()
		await utils.trackLatency(request, env, 'insert_token', () =>
			utils.insertToken(client, hashedToken, email))
	} catch (e) {
		console.log('insert token error:', e)
		return new Response('Database Error, please try again...', { status: 500 })
	}

	env.WAE.writeDataPoint({
		blobs: [
			'token',
			oauth2Client.id,
			request.cf.colo,
			request.cf.country
		],
		indexes: [oauth2Client.id]
	})

	return new Response(JSON.stringify({
		refresh_token: token,
		token_type: 'Bearer'
	}), {
		headers: {
			'content-type': 'application/json'
		}
	})
}
