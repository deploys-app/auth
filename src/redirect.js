import * as utils from './utils'

/**
 * @param {import('@cloudflare/workers-types').Request} request
 * @param {Env} env
 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
 * @returns {Promise<Response>}
 **/
export default async function (request, env, ctx) {
	const url = new URL(request.url)
	const callbackState = url.searchParams.get('state')
	if (!callbackState) {
		return new Response('Missing state parameter', { status: 400 })
	}
	let callbackUrl = url.searchParams.get('callback')
	if (!callbackUrl) {
		return new Response('Missing callback parameter', { status: 400 })
	}
	if (!utils.isUrl(callbackUrl)) {
		return new Response('Invalid callback parameter', { status: 400 })
	}

	const state = utils.generateState()
	const sessionId = utils.generateSessionId()

	await env.DB
		.prepare('insert into sessions (id, data) values (?1, ?2)')
		.bind(sessionId, JSON.stringify({
			state,
			callbackState,
			callbackUrl
		}))
		.run()

	const headers = new Headers()
	headers.append('set-cookie', `s=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax`)

	const target = new URL('https://accounts.google.com/o/oauth2/auth')
	target.searchParams.set('response_type', 'code')
	target.searchParams.set('client_id', env.OAUTH2_CLIENT_ID)
	target.searchParams.set('redirect_uri', 'https://auth.deploys.app/callback')
	target.searchParams.set('scope', 'https://www.googleapis.com/auth/userinfo.email')
	target.searchParams.set('access_type', 'online')
	target.searchParams.set('prompt', 'consent')
	target.searchParams.set('state', state)
	headers.set('location', target.toString())

	return new Response(null, {
		status: 302,
		headers
	})
}
