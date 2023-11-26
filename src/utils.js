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
 * getOAuth2Client gets OAuth2 client from database
 * @param {Env} env
 * @param clientID
 * @returns {Promise<OAuth2Client>}
 */
export async function getOAuth2Client (env, clientID) {
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
 * @param {string} code
 * @param {string} email
 * @returns {Promise<void>}
 */
export async function insertOAuth2Code (env, code, email) {
	await env.DB
		.prepare(`
			insert into oauth2_codes (id, email)
			values (?1, ?2)
		`)
		.bind(code, email)
		.run()
}

/**
 * getOAuth2EmailFromCode gets email from OAuth2 code and delete it
 * @param {Env} env
 * @param {string} code
 * @returns {Promise<?string>}
 */
export async function getOAuth2EmailFromCode (env, code) {
	const data = await env.DB
		.prepare(`
			select email
			from oauth2_codes
			where id = ?1
			  and current_timestamp < datetime(created_at, '+1 hour')
		`)
		.bind(code)
		.first()
	if (!data) {
		return null
	}
	await env.DB
		.prepare(`
			delete from oauth2_codes
			where id = ?1
		`)
		.bind(code)
		.run()
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
 * ensureUser ensures user exists in hyperdrive database
 * @param client
 * @param email
 * @returns {Promise<void>}
 */
export async function ensureUser (client, email) {
	await client.query(`
		insert into users (email, name)
		values ($1, '')
		on conflict (email) do nothing
		returning id, active
	`, [email])
	let res = await client.query(`
		select id, active
		from users
		where email = $1
	`, [email])
	const user = res?.rows[0] || {}
	if (!user.active) {
		throw new Error('user inactive')
	}

	try {
		res = await client.query(`
			select exists(
				select 1
				from billing_accounts
				where owner = $1
			)
		`, [user.id])
		const hasBillingAccount = res?.rows[0]?.exists
		if (!hasBillingAccount) {
			await client.query(`
				insert into billing_accounts (owner, name)
				values ($1, 'My Billing Account')
			`, [user.id])
		}
	} catch (e) { // ignore error
		console.log('ensure billing account error:', e)
	}
}

/**
 * @typedef session
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
