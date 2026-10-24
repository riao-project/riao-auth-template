import { Database, DatabaseRecord, QueryRepository } from '@riao/dbal';
import { Principal } from '@riao/iam';
import {
	AuthenticationProtection,
	AuthenticationRejectedError,
	AuthenticationBlockedError,
} from '@riao/iam/authentication';
import { ExampleAuthentication } from '../../examples';

describe('Authentication driver template contract', () => {
	let auth: ExampleAuthentication;
	let protection: jasmine.SpyObj<AuthenticationProtection>;
	let verify: jasmine.Spy;
	let persist: jasmine.Spy;
	const principal: Principal = {
		id: 'user', login: 'user', name: 'User', type: 'user',
		create_timestamp: new Date(),
	};
	const credentials = { login: 'user', secret: 'test-secret' };

	beforeEach(() => {
		const db = jasmine.createSpyObj<Database>('db', ['getQueryRepository']);
		const repo = jasmine.createSpyObj<QueryRepository<DatabaseRecord>>(
			'repo', ['findOne']
		);
		db.getQueryRepository.and.returnValue(repo);
		protection = jasmine.createSpyObj<AuthenticationProtection>(
			'protection', ['beforeAttempt', 'onFailure', 'onSuccess']
		);
		protection.beforeAttempt.and.resolveTo({ allowed: true });
		protection.onFailure.and.resolveTo();
		protection.onSuccess.and.resolveTo();
		verify = jasmine.createSpy('verify').and.resolveTo(true);
		persist = jasmine.createSpy('persist').and.resolveTo();
		auth = new ExampleAuthentication({
			db, authenticationProtection: protection,
			verifyCredential: verify, persistSuccess: persist,
		});
		spyOn(auth, 'findActivePrincipal').and.resolveTo(principal);
	});

	it('records success only after persistence', async () => {
		persist.and.callFake(async () => {
			expect(protection.onSuccess).not.toHaveBeenCalled();
		});
		expect(await auth.authenticate(credentials)).toBe(principal);
		expect(persist).toHaveBeenCalledOnceWith(principal);
		expect(protection.onSuccess).toHaveBeenCalledTimes(1);
		expect(protection.onFailure).not.toHaveBeenCalled();
		const attempt = protection.onSuccess.calls.mostRecent().args[0];
		expect(attempt).toEqual({ scheme: 'example', subject: 'user' });
	});

	it('does not record or verify blocked attempts', async () => {
		protection.beforeAttempt.and.resolveTo({
			allowed: false, retryAfterSeconds: 30,
		});
		expect(await auth.authenticate(credentials)).toBeNull();
		expect(auth.findActivePrincipal).not.toHaveBeenCalled();
		expect(verify).not.toHaveBeenCalled();
		expect(protection.onSuccess).not.toHaveBeenCalled();
		expect(protection.onFailure).not.toHaveBeenCalled();
	});

	it('records invalid credentials once', async () => {
		verify.and.resolveTo(false);
		expect(await auth.authenticate(credentials)).toBeNull();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
		expect(persist).not.toHaveBeenCalled();
		expect(protection.onSuccess).not.toHaveBeenCalled();
	});

	it('records missing or inactive principals as rejection', async () => {
		(auth.findActivePrincipal as jasmine.Spy).and.resolveTo(null);
		expect(await auth.authenticate(credentials)).toBeNull();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
		expect(verify).not.toHaveBeenCalled();
	});

	it('rejects malformed credentials without verification', async () => {
		expect(await auth.authenticate({ login: '', secret: '' })).toBeNull();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
		expect(verify).not.toHaveBeenCalled();
	});

	it('propagates lookup, verifier, and persistence failures', async () => {
		const error = new Error('Service unavailable');
		(auth.findActivePrincipal as jasmine.Spy).and.rejectWith(error);
		await expectAsync(auth.authenticate(credentials))
			.toBeRejectedWith(error);
		(auth.findActivePrincipal as jasmine.Spy).and.resolveTo(principal);
		verify.and.rejectWith(error);
		await expectAsync(auth.authenticate(credentials))
			.toBeRejectedWith(error);
		verify.and.resolveTo(true);
		persist.and.rejectWith(error);
		await expectAsync(auth.authenticate(credentials))
			.toBeRejectedWith(error);
		expect(protection.onFailure).not.toHaveBeenCalled();
		expect(protection.onSuccess).not.toHaveBeenCalled();
	});

	it('propagates protection failures', async () => {
		const error = new Error('Protection unavailable');
		protection.beforeAttempt.and.rejectWith(error);
		await expectAsync(auth.authenticate(credentials))
			.toBeRejectedWith(error);
		expect(verify).not.toHaveBeenCalled();
		expect(protection.onFailure).not.toHaveBeenCalled();
	});

	it('exposes typed errors for non-principal success APIs', () => {
		const blocked = new AuthenticationBlockedError(30);
		expect(blocked instanceof AuthenticationRejectedError).toBe(true);
		expect(blocked.retryAfterSeconds).toBe(30);
	});

	it('propagates failure recording errors', async () => {
		verify.and.resolveTo(false);
		const error = new Error('Protection recording unavailable');
		protection.onFailure.and.rejectWith(error);
		await expectAsync(auth.authenticate(credentials))
			.toBeRejectedWith(error);
		expect(protection.onSuccess).not.toHaveBeenCalled();
	});

	it('propagates success recording errors after persistence', async () => {
		const error = new Error('Protection recording unavailable');
		protection.onSuccess.and.rejectWith(error);
		await expectAsync(auth.authenticate(credentials))
			.toBeRejectedWith(error);
		expect(persist).toHaveBeenCalledOnceWith(principal);
		expect(protection.onFailure).not.toHaveBeenCalled();
	});
});
