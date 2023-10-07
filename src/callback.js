import * as cookie from 'cookie'
import * as utils from './utils'
import jwtDecode from 'jwt-decode'
import { Client } from 'pg'

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
	const code = url.searchParams.get('code')
	if (!code) {
		return new Response('Missing code parameter', { status: 400 })
	}

	const cookies = cookie.parse(request.headers.get('cookie') || '')
	const sessionId = cookies['s']
	if (!sessionId) {
		return new Response('Missing session', { status: 400 })
	}

	const session = await getSession(env, sessionId)
	if (!session) {
		return failResponse()
	}
	if (session.state !== callbackState) {
		return new Response('Mismatch state', { status: 400 })
	}

	// exchange token
	const v = new URLSearchParams()
	v.set('grant_type', 'authorization_code')
	v.set('code', code)
	v.set('redirect_uri', 'https://auth.deploys.app/callback')
	v.set('client_id', env.OAUTH2_CLIENT_ID)
	v.set('client_secret', env.OAUTH2_CLIENT_SECRET)
	const resp = await fetch('https://oauth2.googleapis.com/token', {
		method: 'POST',
		body: v.toString(),
		headers: {
			'content-type': 'application/x-www-form-urlencoded'
		}
	})
	if (resp.status > 200 || resp.status > 299) {
		return failResponse()
	}
	const respBody = await resp.json()
	const idToken = respBody.id_token
	if (!idToken) {
		return failResponse()
	}
	const decodedToken = jwtDecode(idToken)
	const email = decodedToken?.email
	if (!email) {
		return failResponse()
	}

	const callback = new URL(session.callbackUrl)
	callback.searchParams.set('state', session.callbackState)

	const tk = utils.generateToken()

	try {
		await insertToken(env, tk, email)
	} catch (e) {
		console.log('insert token error:', err)
		return new Response('Cloudflare HyperDrive Error, please try again...', { status: 500 })
	}

	callback.searchParams.set('code', tk)
	return Response.redirect(callback, 302)
}

function failResponse () {
	return Response.redirect('https://www.deploys.app', 302)
}

/**
 * insertToken inserts token into database
 * @param env
 * @param {string} tk token
 * @param {string} email
 * @returns {Promise<void>}
 */
async function insertToken (env, tk, email) {
	const hashedToken = await utils.hash(tk)
	const client = new Client({ connectionString: env.HYPERDRIVE.connectionString })
	await client.connect()
	await client.query(`
		insert into user_tokens (token, email, expires_at)
		values ($1, $2, now() + '7 days')
	`, [hashedToken, email])
}

/**
 * getSession gets session data from database and delete it
 * @param env
 * @param {string} sessionId
 * @returns {Promise<any|null>}
 */
async function getSession (env, sessionId) {
	const data = await env.DB
		.prepare(`
			select data
			from sessions
			where id = ?1
			  and created_at < datetime(current_timestamp, '+1 hour')
		`)
		.bind(sessionId)
		.first('data')
	if (!data) {
		return null
	}

	await env.DB
		.prepare(`
            delete
            from sessions
            where id = ?1
		`)
		.bind(sessionId)
		.run()

	return JSON.parse(data)
}
