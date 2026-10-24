import { Principal } from '@riao/iam';
import {
	Authentication,
	AuthenticationOptions,
} from '@riao/iam/authentication';

export interface ExampleCredentials {
	login: string;
	secret: string;
}

export interface ExampleAuthenticationOptions extends AuthenticationOptions {
	verifyCredential(login: string, secret: string): Promise<boolean>;
	persistSuccess(principal: Principal): Promise<void>;
}

export class ExampleAuthentication extends Authentication<Principal> {
	public constructor(private readonly options: ExampleAuthenticationOptions) {
		super(options);
	}

	public override async authenticate(
		credentials: ExampleCredentials
	): Promise<Principal | null> {
		const attempt = {
			scheme: 'example',
			subject: credentials.login,
		};
		const protection = await this.beforeAuthenticationAttempt(attempt);
		if (!protection.allowed) {
			return null;
		}

		const reject = async (): Promise<null> => {
			await this.recordAuthenticationFailure(attempt);
			return null;
		};
		if (
			typeof credentials.login !== 'string' || !credentials.login ||
			typeof credentials.secret !== 'string' || !credentials.secret
		) {
			return reject();
		}
		const principal = await this.findActivePrincipal({
			where: { login: credentials.login },
		});
		if (!principal) {
			return reject();
		}
		if (!await this.options.verifyCredential(
			credentials.login, credentials.secret
		)) {
			return reject();
		}

		await this.options.persistSuccess(principal);
		await this.recordAuthenticationSuccess(attempt);
		return principal;
	}
}