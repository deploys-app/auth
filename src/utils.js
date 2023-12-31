export async function hash (token) {
	const digest = await crypto.subtle.digest({ name: 'SHA-256' }, new TextEncoder().encode(token))
	return toRawURLEncoding(btoa(String.fromCodePoint(...new Uint8Array(digest))))
}

export function generateToken () {
	const token = new Uint8Array(32)
	crypto.getRandomValues(token)
	return 'deploys-api.' + toRawURLEncoding(btoa(String.fromCodePoint(...token)))
}

export function generateState () {
	const state = new Uint8Array(16)
	crypto.getRandomValues(state)
	return Array.from(state, (x) => x.toString(16).padStart(2, '0')).join('')
}

export function generateCode () {
	const code = new Uint8Array(32)
	crypto.getRandomValues(code)
	return toRawURLEncoding(btoa(String.fromCodePoint(...code)))
}

export function generateSessionId () {
	const sessionId = new Uint8Array(32)
	crypto.getRandomValues(sessionId)
	return Array.from(sessionId, (x) => x.toString(16).padStart(2, '0')).join('')
}

/**
 * isUrl checks if a string is a valid URL
 * @param {string} s
 * @returns {boolean}
 */
export function isUrl (s) {
	try {
		const u = new URL(s)
		return (u.protocol === 'http:' || u.protocol === 'https:') && u.host
	} catch (e) {
		return false
	}
}

/**
 * @typedef OAuth2Client
 * @property {string} id
 * @property {string} secret
 * @property {string} redirectUri
 */

/**
 * getOAuth2Client gets OAuth2 client from cache or database
 * @param {Env} env
 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
 * @param {string} clientID
 * @returns {Promise<OAuth2Client>}
 */
export async function getOAuth2Client (env, ctx, clientID) {
	const cache = caches.default
	const cacheKey = `deploys--auth|oauth2_client|${clientID}`
	const cacheReq = new Request('https://auth.deploys.app/__cache/oauth2_client', {
		cf: {
			cacheTtl: 3600,
			cacheKey,
			cacheTags: ['deploys--auth|oauth2_client']
		}
	})
	const resp = await cache.match(cacheReq)
	if (resp) {
		return resp.json()
	}

	// cache miss
	const data = await getOAuth2ClientFromDB(env, clientID)
	if (!data) {
		ctx.waitUntil(cache.put(cacheReq, new Response(JSON.stringify(data), {
			headers: {
				'content-type': 'application/json',
				'cache-control': 'public, max-age=30'
			}
		})))
		return null
	}

	ctx.waitUntil(cache.put(cacheReq, new Response(JSON.stringify(data), {
		headers: {
			'content-type': 'application/json',
			'cache-control': 'public, max-age=3600'
		}
	})))

	return data
}

/**
 * getOAuth2ClientFromDB gets OAuth2 client from database
 * @param {Env} env
 * @param {string} clientID
 * @returns {Promise<OAuth2Client>}
 */
export async function getOAuth2ClientFromDB (env, clientID) {
	const data = await env.DB
		.prepare('select id, secret, redirect_uri from oauth2_clients where id = ?')
		.bind(clientID)
		.first()
	if (!data) {
		return null
	}
	return {
		id: data.id,
		secret: data.secret,
		redirectUri: data.redirect_uri
	}
}

/**
 * insertOAuth2Code inserts OAuth2 code into database
 * @param {Env} env
 * @param {string} clientId
 * @param {string} code
 * @param {string} email
 * @returns {Promise<void>}
 */
export async function insertOAuth2Code (env, clientId, code, email) {
	await env.DB
		.prepare(`
			insert into oauth2_codes (id, client_id, email)
			values (?1, ?2, ?3)
		`)
		.bind(code, clientId, email)
		.run()
}

/**
 * getOAuth2EmailFromCode gets email from OAuth2 code and delete it
 * @param {import('@cloudflare/workers-types').Request} request
 * @param {Env} env
 * @param {string} clientId
 * @param {string} code
 * @returns {Promise<?string>}
 */
export async function getOAuth2EmailFromCode (request, env, clientId, code) {
	const data = await trackLatency(request, env, 'get_oauth2_email_from_code', () =>
		env.DB
			.prepare(`
			delete from oauth2_codes
			where id = ?1
			  and client_id = ?2
			  and current_timestamp < datetime(created_at, '+1 hour')
			returning email
		`)
			.bind(code, clientId)
			.first())
	if (!data) {
		return null
	}
	return data.email
}

/**
 * insertToken inserts token into hyperdrive database
 * @param {Client} client
 * @param {string} hashedToken
 * @param {string} email
 * @returns {Promise<void>}
 */
export async function insertToken (client, hashedToken, email) {
	await client.query(`
		insert into user_tokens (token, email, expires_at)
		values ($1, $2, now() + '7 days')
	`, [hashedToken, email])
}

/**
 * @typedef session
 * @property {string} clientId
 * @property {string} state
 * @property {string} callbackState
 * @property {string} callbackUrl
 */

/**
 * getSession gets session data from database and delete it
 * @param env
 * @param {string} sessionId
 * @returns {Promise<?session>}
 */
export async function getSession (env, sessionId) {
	/** @type {string} */
	const data = await env.DB
		.prepare(`
			select data
			from sessions
			where id = ?1
			  and current_timestamp < datetime(created_at, '+1 hour')
		`)
		.bind(sessionId)
		.first('data')
	if (!data) {
		return null
	}

	await env.DB
		.prepare('delete from sessions where id = ?1')
		.bind(sessionId)
		.run()

	return JSON.parse(data)
}

/**
 * saveSession saves session data to database
 * @param {Env} env
 * @param {string} sessionId
 * @param {session} data
 * @returns {Promise<void>}
 */
export async function saveSession (env, sessionId, data) {
	await env.DB
		.prepare('insert into sessions (id, data) values (?1, ?2)')
		.bind(sessionId, JSON.stringify(data))
		.run()
}

function toRawURLEncoding (s) {
	return s.replace(/=*$/, '').replace(/\+/g, '-').replace(/\//g, '_')
}

/**
 * @template T
 * @typedef {T | Promise<T>} MaybePromise
 */

/**
 * trackLatency tracks latency of a function
 * @template T
 * @param {import('@cloudflare/workers-types').Request} request
 * @param {Env} env
 * @param {string} name
 * @param {() => MaybePromise<T>} f
 * @returns {Promise<T>}
 */
export async function trackLatency (request, env, name, f) {
	const start = Date.now()
	const res = await f()
	env.WAE.writeDataPoint({
		blobs: [
			'latency',
			name,
			request.cf.colo
		],
		doubles: [Date.now() - start],
		indexes: ['latency']
	})
	return res
}
