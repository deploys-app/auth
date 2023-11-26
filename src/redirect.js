import * as utils from './utils'

/**
 * @param {import('@cloudflare/workers-types').Request} request
 * @param {Env} env
 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
 * @returns {Promise<import('@cloudflare/workers-types').Response>}
 **/
export default async function (request, env, ctx) {
	const url = new URL(request.url)

	const clientId = url.searchParams.get('client_id')
	if (!clientId) {
		return new Response('Missing client_id parameter', { status: 400 })
	}
	const callbackState = url.searchParams.get('state')
	if (!callbackState) {
		return new Response('Missing state parameter', { status: 400 })
	}
	const callbackUrl = url.searchParams.get('redirect_uri')
	if (!callbackUrl) {
		return new Response('Missing redirect_uri parameter', { status: 400 })
	}
	if (!utils.isUrl(callbackUrl)) {
		return new Response('Invalid redirect_uri parameter', { status: 400 })
	}

	const oauth2Client = await utils.getOAuth2Client(env, clientId)
	if (!oauth2Client) {
		return new Response('Invalid client_id parameter', { status: 400 })
	}
	const pattern = '^' + (oauth2Client.redirectUri || '')
		.replaceAll('.', '\\.')
		.replaceAll('/', '\\/')
		.replaceAll('*', '.*') +
		'$'

	const re = new RegExp(pattern)
	if (!re.test(callbackUrl)) {
		return new Response('Invalid redirect_uri parameter', { status: 400 })
	}

	const state = utils.generateState()
	const sessionId = utils.generateSessionId()

	await utils.saveSession(env, sessionId, {
		clientId: oauth2Client.id,
		state,
		callbackState,
		callbackUrl
	})

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
