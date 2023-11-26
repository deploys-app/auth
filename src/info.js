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
	const hashedToken = await hash(token)
	const email = await getEmailFromToken(env, hashedToken)
	if (!email) {
		return failResponse('auth: unauthorized')
	}
	return new Response(JSON.stringify({
		ok: true,
		result: {
			email
		}
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
 * getEmailFromToken gets the email from the token.
 * @param {Env} env
 * @param {string} hashedToken
 * @returns {Promise<?string>}
 */
async function getEmailFromToken (env, hashedToken) {
	const r = await env.DB
		.prepare(`
			select email
			from tokens
			where id = ?1 and expires_at > current_timestamp
		`)
		.bind(hashedToken)
		.first()
	return r?.email
}
