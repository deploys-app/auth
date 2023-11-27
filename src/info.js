import { hash } from './utils'

/**
 * @param {import('@cloudflare/workers-types').Request} request
 * @param {Env} env
 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
 * @returns {Promise<import('@cloudflare/workers-types').Response>}
 **/
export default async function info (request, env, ctx) {
	const token = extractAuthToken(request.headers.get('authorization') ?? '')
	if (!token) {
		return failResponse('auth: unauthorized')
	}

	const start = Date.now()

	/** @type {?TokenInfo} */
	let tokenInfo = null

	if (token.startsWith('deploys-api.')) {
		const hashedToken = await hash(token)
		tokenInfo = await getTokenInfo(env, hashedToken)
	} else if (token.startsWith('ya29.')) {
		tokenInfo = await getGoogleTokenInfo(env, token)
	}

	if (!tokenInfo) {
		return failResponse('auth: unauthorized')
	}

	const duration = Date.now() - start

	env.WAE.writeDataPoint({
		blobs: [
			'info',
			tokenInfo.clientId,
			request.cf.colo,
			request.cf.country
		],
		doubles: [duration],
		indexes: [tokenInfo.clientId]
	})

	return new Response(JSON.stringify({
		ok: true,
		result: tokenInfo
	}))
}

/**
 * extractAuthToken extracts the auth token from the Authorization header.
 * @param {string} auth
 * @returns {string}
 */
function extractAuthToken (auth) {
	const tk = auth.trim()
	if (!tk) {
		return ''
	}
	const parts = /^bearer (.+)$/i.exec(tk)
	if (parts?.length !== 2) {
		return ''
	}
	return parts[1].trim()
}

function failResponse (error) {
	return new Response(JSON.stringify({
		ok: false,
		error: {
			message: error
		}
	}))
}

/**
 * @typedef TokenInfo
 * @property {string} email
 * @property {string} clientId
 */

/**
 * getTokenInfo gets the tokenInfo from the hashed token.
 * @param {Env} env
 * @param {string} hashedToken
 * @returns {Promise<?TokenInfo>}
 */
async function getTokenInfo (env, hashedToken) {
	const r = await env.DB
		.prepare(`
			select email, client_id
			from tokens
			where id = ?1 and expires_at > current_timestamp
		`)
		.bind(hashedToken)
		.first()
	if (!r) {
		return null
	}
	return {
		email: r.email,
		clientId: r.client_id
	}
}

/**
 * getGoogleTokenInfo gets the tokenInfo from the Google token.
 * @param {Env} env
 * @param {string} token
 * @returns {Promise<?TokenInfo>}
 */
async function getGoogleTokenInfo (env, token) {
	const r = await fetch('https://www.googleapis.com/userinfo/v2/me', {
		headers: {
			authorization: `Bearer ${token}`
		}
	})
	if (!r.ok) {
		return null
	}
	const body = await r.json()
	if (!body.email) {
		return null
	}
	return {
		email: body.email,
		clientId: 'google'
	}
}
