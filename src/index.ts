import { defineEndpoint } from '@directus/extensions-sdk';
import Redis from 'ioredis';
import ms from 'ms';
import crypto from 'crypto';
import { RedirectWhitelistHelper } from "./helpers/RedirectWhitelistHelper";
import { createKv, KvLocal, KvRedis } from '@directus/memory';
import { NanoidHelper } from "./helpers/NanoidHelper";

const env = process.env;
const endpoint = "pkce";
const PUBLIC_URL = env.PUBLIC_URL || '';
const CALLBACK_FALLBACK_URL = env.CALLBACK_FALLBACK_URL || '';

function getUrlToProviderLogin(providerName: string, redirectURL: string) {
	return `${PUBLIC_URL}/auth/login/${providerName}?redirect=${redirectURL}`;
}

// https://www.rfc-editor.org/rfc/rfc7636

type AuthorizationCodeAndRedirectType = {
	authorization_code: string,
	redirect_url: string
}

interface KvStorageImplementation {
	set(key: string, value: string): Promise<"OK">
	get(key: string): Promise<string | null>
	del(...args: string[]): Promise<number>
}

class MyKvStorageRedis implements KvStorageImplementation {
	private duration: number
	private redis: Redis
	constructor(redisUrl: string, duration: number) {
		this.duration = duration;
		this.redis = new Redis(redisUrl); // Assumes env.REDIS is set to "redis://rocket-meals-cache:6379"
	}

	del(...args: string[]): Promise<number> {
		return this.redis.del(args);
	}

	get(key: string): Promise<string | null> {
		return this.redis.get(key);
	}

	set(key: string, value: string): Promise<"OK"> {
		return this.redis.set(key, value, 'EX', this.duration);
	}

}

class MyKvStorageMemory implements KvStorageImplementation {
	private cache: KvLocal | KvRedis;
	private duration: number;

	constructor(duration: number) {
		this.duration = duration;
		this.cache = createKv({
			type: 'local',
		});
	}

	async del(...args: string[]): Promise<number> {
		let amountDeleted = 0;
		for (let arg of args) {
			await this.cache.delete(arg);
			amountDeleted++;
		}
		return amountDeleted;
	}

	async get(key: string): Promise<string | null> {
		const cachedItem = await this.cache.get<{ value: string; expiration: number }>(key);

		if (!cachedItem) {
			return null; // Key not found or value is null
		}

		const { value, expiration } = cachedItem;
		const currentTime = Date.now();

		if (currentTime > expiration) {
			// If the current time is past the expiration, remove the item and return null
			await this.cache.delete(key);
			return null;
		}

		return value; // Return the value if it has not expired
	}

	async set(key: string, value: string): Promise<"OK"> {
		const expiration = Date.now() + this.duration * 1000; // Calculate expiration time in milliseconds
		const item = { value, expiration }; // Create an object with value and expiration
		await this.cache.set(key, item); // Store the object in the cache
		return "OK";
	}
}


class KvStorage {
	static prefix_code_challenge = "pkce_code_challenge_";
	static prefix_save_session = "pkce_save_session_"

	private kvImplementation: KvStorageImplementation

	constructor(redisUrl: string | null, maxTtl?: number) {
		const defaultDuration = 300; // max Time To Live (TTL) to 300s = 5min
		const duration = maxTtl || defaultDuration;

		//this.kvImplementation = !!redisUrl ? new MyKvStorageRedis(redisUrl, duration)
		this.kvImplementation = redisUrl ? new MyKvStorageRedis(redisUrl, duration) : new MyKvStorageMemory(duration);
	}

	async setCodeChallenge(authorization_code: string, code_challenge: CodeChallengeRedisEntryType) {
		await this.kvImplementation.set(KvStorage.prefix_code_challenge + authorization_code, JSON.stringify(code_challenge))
	}

	async getCodeChallenge(authorization_code: string) {
		let savedKey = await this.kvImplementation.get(KvStorage.prefix_code_challenge + authorization_code);
		if (savedKey) {
			try {
				let obj = JSON.parse(savedKey) as CodeChallengeRedisEntryType
				return obj;
			} catch (error) {
				// Optionally log the error
				console.error(`Failed to parse CodeChallenge for key ${KvStorage.prefix_code_challenge + authorization_code}:`, error);
				return null;
			}
		}
		return null;
	}

	async setStateInformation(state: string, authCodeAndRedirect: AuthorizationCodeAndRedirectType) {
		await this.kvImplementation.set(KvStorage.prefix_save_session + state, JSON.stringify(authCodeAndRedirect));
	}

	async getStateInformation(state: string): Promise<AuthorizationCodeAndRedirectType | null> {
		let savedKey = await this.kvImplementation.get(KvStorage.prefix_save_session + state);
		if (savedKey) {
			try {
				let obj = JSON.parse(savedKey) as AuthorizationCodeAndRedirectType
				return obj;
			} catch (error) {
				// Optionally log the error
				console.error(`Failed to parse StateInformation for key ${KvStorage.prefix_save_session + state}:`, error);
				return null;
			}
		}
		return null;
	}

	async clearStateInformation(state: string) {
		await this.kvImplementation.del(KvStorage.prefix_save_session + state);
	}

	async clearAssociatedCodeChallengeFromCode(authorization_code: string) {
		await this.kvImplementation.del(KvStorage.prefix_code_challenge + authorization_code);
	}
}

type CodeChallengeRedisEntryType = {
	code_challenge: string,
	code_challenge_method: string,
	directus_refresh_token: string | null
	directus_session_token: string | null
}

class CodeChallengeMethods {
	static METHOD_S256 = "S256"
	static METHOD_plain = "plain"
}

async function generateRefreshToken(accountability: any, userId: string, knex: any) {
	// we need to obtain the directus_refresh_token from the directus_session_token
	if (!userId) {
		throw new Error("No user Id given")
	}

	/**
	 * Start of copy: https://github.com/directus/directus/blob/main/api/src/services/authentication.ts Login
	 */
	const refreshToken = await NanoidHelper.getNanoid(64);
	const refreshTokenTTL = env['REFRESH_TOKEN_TTL'] || '0';
	const msRefreshTokenTTL: number = ms(String(refreshTokenTTL)) || 0;
	const refreshTokenExpiration = new Date(Date.now() + msRefreshTokenTTL);
	console.log(`PKCE: Generating refresh token. TTL string: "${refreshTokenTTL}", ms: ${msRefreshTokenTTL}, Expiration: ${refreshTokenExpiration.toISOString()}`);

	await knex('directus_sessions').insert({
		token: refreshToken,
		user: userId,
		expires: refreshTokenExpiration,
		ip: accountability?.ip,
		user_agent: accountability?.userAgent,
		origin: accountability?.origin,
	});

	await knex('directus_sessions').delete().where('expires', '<', new Date());

	return refreshToken;
}


function getEnvVarNameAuthProviderRedirectAllowList(provider: string) {
	const providerCaps = provider.toUpperCase() // makes from "google" --> "GOOGLE"
	return `AUTH_${providerCaps}_REDIRECT_ALLOW_LIST`
}

function getProviderRedirectAllowList(provider: string): string[] {
	let allowed_redirect_urls_raw = env?.[getEnvVarNameAuthProviderRedirectAllowList(provider)] as string[] | string
	let allowed_redirect_urls: string[] = []
	if (allowed_redirect_urls_raw) {
		if (typeof allowed_redirect_urls_raw === "string") {
			allowed_redirect_urls = allowed_redirect_urls_raw?.split(",");
		} else {
			allowed_redirect_urls = allowed_redirect_urls_raw;
		}
	}
	return allowed_redirect_urls;
}

async function isRedirectUrlWhitelisted(redirect_url_as_url: URL, provider: string) {
	const redirect_url = redirect_url_as_url.toString();
	const allowed_redirect_urls = getProviderRedirectAllowList(provider);
	if (redirect_url.startsWith(PUBLIC_URL)) { // we will always allow the redirect to the server page
		return true;
	} else {
		return RedirectWhitelistHelper.isRedirectUrlAllowedForWhitelistEntriesWithSimpleWildcards(allowed_redirect_urls, redirect_url_as_url)
	}
}

function getRegisteredAuthProviderList() {
	const configured_auth_providers_raw = env?.["AUTH_PROVIDERS"]
	let configured_auth_providers: string[] = [];
	if (Array.isArray(configured_auth_providers_raw)) {
		configured_auth_providers = configured_auth_providers_raw;
	} else if (!!configured_auth_providers_raw) {
		configured_auth_providers = configured_auth_providers_raw?.split(",");
	}
	return configured_auth_providers;
}

function checkIfProviderRegistered(provider: string) {
	let configured_auth_providers = getRegisteredAuthProviderList()
	return configured_auth_providers.includes(provider);
}

function generateAuthorizationCode(amountBytes?: number) {
	const bytesMinAmount = 32;
	const usedAmountBytes = amountBytes || bytesMinAmount;
	const authorization_code = crypto.randomBytes(usedAmountBytes).toString('hex');

	return authorization_code;
}

function generateStateCode() {
	const bytesDefaultAmount = 32;

	return crypto.randomBytes(bytesDefaultAmount).toString('hex');
}

export default defineEndpoint({
	id: endpoint,
	handler: (router, {
		database,
		env, logger }) => {

		const redisUrl = env?.["REDIS"];
		let validRedisUrl: string | null = null;
		if (!redisUrl || redisUrl.length === 0) {
			return;
		} else {
			validRedisUrl = redisUrl;
		}

		const storage = new KvStorage(validRedisUrl, 300);

		// 4.1.  Client Creates a Code Verifier - Mobile App
		// 4.2.  Client Creates the Code Challenge - Mobile App

		// 4.3.  Client Sends the Code Challenge with the Authorization Request - Directus Extension
		router.post('/authorize', async (req, res) => {
			const { provider, code_challenge, redirect_url, code_challenge_method } = req.body;
			logger.info(`Received request to ${endpoint}/authorize with body: ${JSON.stringify(req.body)}`);

			//   The client sends the code challenge as part of the OAuth 2.0
			//    Authorization Request (Section 4.1.1 of [RFC6749]) using the
			//    following additional parameters:
			//
			//    code_challenge
			//       REQUIRED.  Code challenge.
			const code_challenge_app = code_challenge;
			if (!code_challenge_app) {
				// 4.4.1.  Error Response
				//
				//    If the server requires Proof Key for Code Exchange (PKCE) by OAuth
				//    public clients and the client does not send the "code_challenge" in
				//    the request, the authorization endpoint MUST return the authorization
				//    error response with the "error" value set to "invalid_request".  The
				//    "error_description" or the response of "error_uri" SHOULD explain the
				//    nature of error, e.g., code challenge required.
				return res.status(400).json({ error: 'Missing required parameters code_challenge.' });
			}

			//
			//    code_challenge_method
			//       OPTIONAL, defaults to "plain" if not present in the request.  Code
			//       verifier transformation method is "S256" or "plain".
			let code_challenge_method_app = code_challenge_method || CodeChallengeMethods.METHOD_plain;

			if (!(code_challenge_method_app === CodeChallengeMethods.METHOD_S256 || code_challenge_method_app === CodeChallengeMethods.METHOD_plain)) {
				// Clients are
				//    permitted to use "plain" only if they cannot support "S256" for some
				//    technical reason and know via out-of-band configuration that the
				//    server supports "plain".
				return res.status(400).json({ error: `Code challenge method provided ${code_challenge_method_app} method has to be either "${CodeChallengeMethods.METHOD_S256}" or "${CodeChallengeMethods.METHOD_plain}"` });
			}

			if (!provider) {
				return res.status(400).json({ error: 'Missing required parameter provider. Has to be an auth provider configured in directus.' });
			}
			const providerIsRegistered = checkIfProviderRegistered(provider);
			if (!providerIsRegistered) {
				return res.status(400).json({ error: `Provider ${provider} not listed in AUTH_PROVIDERS` });
			}


			if (!redirect_url) {
				return res.status(400).json({ error: 'Missing required parameter redirect_url' });
			}
			let redirect_url_well_formed = RedirectWhitelistHelper.getUrlFromString(redirect_url);
			if (!redirect_url_well_formed) {
				return res.status(400).json({ error: `Parameter redirect_url is not a well formed url: ${redirect_url}` });
			}
			let redirect_url_is_allowed = isRedirectUrlWhitelisted(redirect_url_well_formed, provider);
			if (!redirect_url_is_allowed) {
				return res.status(400).json({ error: `Redirect url ${redirect_url} is not included in the redirect allow list for the provider ${provider}` });
			}

			// Store the code_challenge_app with the state as key in Redis
			// When the server issues the authorization code in the authorization
			//    response, it MUST associate the "code_challenge" and
			//    "code_challenge_method" values with the authorization code so it can
			//    be verified later.
			const authorization_code = generateAuthorizationCode()
			// Typically, the "code_challenge" and "code_challenge_method" values
			//    are stored in encrypted form in the "code" itself but could
			//    alternatively be stored on the server associated with the code.  The
			//    server MUST NOT include the "code_challenge" value in client requests
			//    in a form that other entities can extract.
			await storage.setCodeChallenge(authorization_code, {
				code_challenge: code_challenge_app,
				code_challenge_method: code_challenge_method_app,
				directus_session_token: null,
				directus_refresh_token: null, // currently we have not saved the directus_refresh_token. After the OAuth2 Flow we will add it there
			});

			// We will now use directus implemented OAuth2 Flow and just save the verified user then, so that the directus_refresh_token can be received when passing the authorization_code and code_verifier
			const state = generateStateCode() // create a state, so that we know upon redirect which authorization code was in this session

			await storage.setStateInformation(state, {
				authorization_code: authorization_code,
				redirect_url: redirect_url_well_formed.toString()
			});

			const redirectUrlToSaveSession = `${PUBLIC_URL}/${endpoint}/save-session?state=${state}&redirect_url=${encodeURIComponent(redirect_url_well_formed.toString())}`;

			const urlToProviderLogin = getUrlToProviderLogin(provider, redirectUrlToSaveSession);
			return res.json({
				url_to_provider_login: urlToProviderLogin
			})
		});

		// Route to save the session using state after successful OAuth2 redirect
		router.get('/save-session', async (req, res) => {
			logger.info(`Received request to ${endpoint}/save-session with query: ${JSON.stringify(req.query)} and cookies: ${JSON.stringify(req.cookies)}`);

			const { state, reason } = req.query;
			if (reason) {
				logger.error(`Error during OAuth2 flow: ${reason}`);
				return res.redirect(CALLBACK_FALLBACK_URL + "?reason=" + encodeURIComponent(reason.toString()));
			}

			if (!state) {
				return res.status(400).json({ error: 'Missing required parameter state.' });
			}
			const stateAsString = state.toString();

			const directus_session_token = req.cookies.directus_session_token;
			if (!directus_session_token) {
				return res.status(400).json({ error: 'Missing directus_session_token in cookies.' });
			}

			let saved_authorization_code_and_redirect = await storage.getStateInformation(stateAsString);
			if (!saved_authorization_code_and_redirect) {
				return res.status(400).json({ error: 'No information found for state. Might be too long' });
			}
			const redirect_url = saved_authorization_code_and_redirect.redirect_url
			const authorization_code = saved_authorization_code_and_redirect.authorization_code
			if (!authorization_code || !redirect_url) {
				return res.status(400).json({ error: 'No information found for state. Might be too long / outdated' });
			}

			await storage.clearStateInformation(stateAsString); // clear state information, as we got all the information and they exist.

			const storedCodeChallenge = await storage.getCodeChallenge(authorization_code);
			if (!storedCodeChallenge || !storedCodeChallenge.code_challenge_method || !storedCodeChallenge.code_challenge) {
				return res.status(400).json({ error: 'No information found for saved authorization code. Might be too long' });
			}

			// @ts-ignore
			const accountability = req?.accountability;
			logger.info(`Accountability: ${JSON.stringify(accountability)}`); // Log the accountability for debugging

			// @ts-ignore
			const userId = req?.accountability?.user;
			if (!accountability || !userId) {
				return res.status(400).json({ error: 'No accountability or userId found.' });
			}
			logger.info(`User ID: ${userId}`); // Log the user ID for debugging

			let directus_refresh_token = await generateRefreshToken(accountability, userId, database);

			// Save the directus refresh token in the code challenge
			await storage.setCodeChallenge(saved_authorization_code_and_redirect.authorization_code, {
				code_challenge: storedCodeChallenge?.code_challenge,
				code_challenge_method: storedCodeChallenge?.code_challenge_method,
				directus_refresh_token: directus_refresh_token,
				directus_session_token: directus_session_token,
			});

			// now redirect the user to the previously verified redirect url
			const redirect_url_with_authorization_code = redirect_url + "?code=" + authorization_code;
			return res.redirect(redirect_url_with_authorization_code) // The user in the native app (using Auth WebBrowser) or SPA, will get the authorization code
		});

		// 4.5.  Client Sends the Authorization Code and the Code Verifier to the Token Endpoint
		router.post('/token', async (req, res) => {
			const { code, code_verifier } = req.body;

			//    code_verifier
			//       REQUIRED.  Code verifier
			const code_verifier_app = code_verifier;
			if (!code_verifier_app) {
				return res.status(400).json({ error: 'Missing required parameter: code_verifier.' });
			}

			const authorization_code = code;
			const storedCodeChallenge = await storage.getCodeChallenge(authorization_code);
			if (!storedCodeChallenge) {
				return res.status(400).json({ error: 'Invalid or expired state.' });
			}

			try {
				// Validate the code_verifier_app against the stored code_challenge_app
				let generatedChallenge = crypto
					.createHash('sha256')
					.update(code_verifier_app)
					.digest('base64url');

				if (storedCodeChallenge.code_challenge_method === CodeChallengeMethods.METHOD_plain) {
					// 4.6
					// If the "code_challenge_method" from Section 4.3 was "plain", they are
					//    compared directly, i.e.:
					//
					//    code_verifier == code_challenge.
					generatedChallenge = code_verifier_app;
				}


				// Secure comparison of the code challenge
				if (!crypto.timingSafeEqual(Buffer.from(generatedChallenge), Buffer.from(storedCodeChallenge.code_challenge))) {
					return res.status(400).json({ error: 'Invalid code verifier.' });
				}

				const directus_session_token = storedCodeChallenge.directus_session_token;
				if (!directus_session_token) {
					return res.status(400).json({ error: 'Session not found or expired. No directus_refresh_token found' });
				}

				const directus_refresh_token = storedCodeChallenge.directus_refresh_token;

				// If valid, clear the stored state and session
				await storage.clearAssociatedCodeChallengeFromCode(authorization_code);

				// Return the session or token associated with the validated request
				return res.json({
					message: 'Validation successful',
					directus_refresh_token: directus_refresh_token,
					directus_session_token: directus_session_token // https://github.com/directus/directus/issues/21757#issuecomment-1992539944  https://github.com/directus/directus/issues/21757
				});
			} catch (error: any) {
				return res.status(500).json({ error: 'Internal server error.', message: error.toString() });
			}
		});
	},
});
