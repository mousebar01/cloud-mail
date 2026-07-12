import BizError from '../error/biz-error';
import accountService from './account-service';
import orm from '../entity/orm';
import user from '../entity/user';
import email from '../entity/email';
import { and, asc, count, desc, eq, inArray, ne, sql } from 'drizzle-orm';
import { emailConst, isDel, roleConst, userConst } from '../const/entity-const';
import kvConst from '../const/kv-const';
import KvConst from '../const/kv-const';
import cryptoUtils from '../utils/crypto-utils';
import emailService from './email-service';
import dayjs from 'dayjs';
import permService from './perm-service';
import roleService from './role-service';
import emailUtils from '../utils/email-utils';
import saltHashUtils from '../utils/crypto-utils';
import constant from '../const/constant';
import { t } from '../i18n/i18n'
import reqUtils from '../utils/req-utils';
import {oauth} from "../entity/oauth";
import oauthService from "./oauth-service";

const DEACTIVATED_MARKERS = [
	'account has been deactivated',
	'your account has been deactivated',
	'account deactivated',
	'access deactivated',
	'账号已被停用',
	'账户已被停用',
	'账号已停用',
	'账户已停用'
];
const PLUS_MARKERS = [
	'chatgpt plus subscription',
	'successfully subscribed to chatgpt plus',
	'subscribed to chatgpt plus',
	'你已成功订阅 chatgpt plus',
	'成功订阅 chatgpt plus'
];

const userService = {

	async loginUserInfo(c, userId) {

		const userRow = await userService.selectById(c, userId);

		if (!userRow) {
			throw new BizError(t('authExpired'), 401);
		}

		const [account, roleRow, permKeys] = await Promise.all([
			accountService.selectByEmailIncludeDel(c, userRow.email),
			roleService.selectById(c, userRow.type),
			userRow.email === c.env.admin ? Promise.resolve(['*']) : permService.userPermKeys(c, userId)
		]);

		const user = {};
		user.userId = userRow.userId;
		user.sendCount = userRow.sendCount;
		user.email = userRow.email;
		user.account = account;
		user.name = account.name;
		user.permKeys = permKeys;
		user.role = roleRow;
		user.type = userRow.type;

		if (c.env.admin === userRow.email) {
			user.role = constant.ADMIN_ROLE
			user.type = 0;
		}

		return user;
	},


	async resetPassword(c, params, userId) {

		const { password } = params;

		if (password.length < 6) {
			throw new BizError(t('pwdMinLength'));
		}
		const { salt, hash } = await cryptoUtils.hashPassword(password);
		await orm(c).update(user).set({ password: hash, salt: salt }).where(eq(user.userId, userId)).run();
	},

	selectByEmail(c, email) {
		return orm(c).select().from(user).where(
			and(
				eq(user.email, email),
				eq(user.isDel, isDel.NORMAL)))
			.get();
	},

	async insert(c, params) {
		const { userId } = await orm(c).insert(user).values({ ...params }).returning().get();
		return userId;
	},

	selectByEmailIncludeDel(c, email) {
		return orm(c).select().from(user).where(sql`${user.email} COLLATE NOCASE = ${email}`).get();
	},

	selectByIdIncludeDel(c, userId) {
		return orm(c).select().from(user).where(eq(user.userId, userId)).get();
	},

	selectById(c, userId) {
		return orm(c).select().from(user).where(
			and(
				eq(user.userId, userId),
				eq(user.isDel, isDel.NORMAL)))
			.get();
	},

	async delete(c, userId) {
		await orm(c).update(user).set({ isDel: isDel.DELETE }).where(eq(user.userId, userId)).run();
		await c.env.kv.delete(kvConst.AUTH_INFO + userId)
	},

	async physicsDelete(c, params) {
		let { userIds } = params;
		userIds = userIds.split(',').map(Number);
		await accountService.physicsDeleteByUserIds(c, userIds);
		await oauthService.deleteByUserIds(c, userIds);
		await orm(c).delete(user).where(inArray(user.userId, userIds)).run();
	},

	async list(c, params) {

		let { num, size, email, timeSort, status } = params;

		size = Number(size);
		num = Number(num);
		timeSort = Number(timeSort);
		params.isDel = Number(params.isDel);
		if (size > 50) {
			size = 50;
		}

		num = (num - 1) * size;

		const conditions = [];

		if (status > -1) {
			conditions.push(eq(user.status, status));
			conditions.push(eq(user.isDel, isDel.NORMAL));
		}


		if (email) {
			conditions.push(sql`${user.email} COLLATE NOCASE LIKE ${'%'+ email + '%'}`);
		}


		if (params.isDel) {
			conditions.push(eq(user.isDel, params.isDel));
		}


		const query = orm(c).select({
			...user,
			username: oauth.username,
			trustLevel: oauth.trustLevel,
			avatar: oauth.avatar,
			name: oauth.name
		}).from(user).leftJoin(oauth, eq(oauth.userId, user.userId))
			.where(and(...conditions));


		if (timeSort) {
			query.orderBy(asc(user.userId));
		} else {
			query.orderBy(desc(user.userId));
		}

		const list = await query.limit(size).offset(num);

		const { total } = await orm(c)
			.select({ total: count() })
			.from(user)
			.where(and(...conditions)).get();
		const userIds = list.map(user => user.userId);

		const types = [...new Set(list.map(user => user.type))];

		const [emailCounts, delEmailCounts, sendCounts, delSendCounts, accountCounts, delAccountCounts, roleList] = await Promise.all([
			emailService.selectUserEmailCountList(c, userIds, emailConst.type.RECEIVE),
			emailService.selectUserEmailCountList(c, userIds, emailConst.type.RECEIVE, isDel.DELETE),
			emailService.selectUserEmailCountList(c, userIds, emailConst.type.SEND),
			emailService.selectUserEmailCountList(c, userIds, emailConst.type.SEND, isDel.DELETE),
			accountService.selectUserAccountCountList(c, userIds),
			accountService.selectUserAccountCountList(c, userIds, isDel.DELETE),
			roleService.selectByIdsHasPermKey(c, types,'email:send')
		]);

		const receiveMap = Object.fromEntries(emailCounts.map(item => [item.userId, item.count]));
		const sendMap = Object.fromEntries(sendCounts.map(item => [item.userId, item.count]));
		const accountMap = Object.fromEntries(accountCounts.map(item => [item.userId, item.count]));

		const delReceiveMap = Object.fromEntries(delEmailCounts.map(item => [item.userId, item.count]));
		const delSendMap = Object.fromEntries(delSendCounts.map(item => [item.userId, item.count]));
		const delAccountMap = Object.fromEntries(delAccountCounts.map(item => [item.userId, item.count]));

		for (const user of list) {

			const userId = user.userId;

			user.receiveEmailCount = receiveMap[userId] || 0;
			user.sendEmailCount = sendMap[userId] || 0;
			user.accountCount = accountMap[userId] || 0;

			user.delReceiveEmailCount = delReceiveMap[userId] || 0;
			user.delSendEmailCount = delSendMap[userId] || 0;
			user.delAccountCount = delAccountMap[userId] || 0;

			const roleIndex = roleList.findIndex(roleRow => user.type === roleRow.roleId);
			let sendAction = {};

			if (roleIndex > -1) {
				sendAction.sendType = roleList[roleIndex].sendType;
				sendAction.sendCount = roleList[roleIndex].sendCount;
				sendAction.hasPerm = true;
			} else {
				sendAction.hasPerm = false;
			}

			if (user.email === c.env.admin) {
				sendAction.sendType = constant.ADMIN_ROLE.sendType;
				sendAction.sendCount = constant.ADMIN_ROLE.sendCount;
				sendAction.hasPerm = true;
				user.type = 0
			}

			user.sendAction = sendAction;
		}

		return { list, total };
	},

	async updateUserInfo(c, userId, recordCreateIp = false) {



		const activeIp = reqUtils.getIp(c);

		const {os, browser, device} = reqUtils.getUserAgent(c);

		const params = {
			os,
			browser,
			device,
			activeIp,
			activeTime: dayjs().format('YYYY-MM-DD HH:mm:ss')
		};

		if (recordCreateIp) {
			params.createIp = activeIp;
		}

		await orm(c)
			.update(user)
			.set(params)
			.where(eq(user.userId, userId))
			.run();
	},

	async setPwd(c, params) {

		const { password, userId } = params;
		await this.resetPassword(c, { password }, userId);
		await c.env.kv.delete(KvConst.AUTH_INFO + userId);
	},

	async setStatus(c, params) {

		const { status, userId } = params;

		await orm(c)
			.update(user)
			.set({ status })
			.where(eq(user.userId, userId))
			.run();

		if (status === userConst.status.BAN) {
			await c.env.kv.delete(KvConst.AUTH_INFO + userId);
		}
	},

	async setType(c, params) {

		const { type, userId } = params;

		const roleRow = await roleService.selectById(c, type);

		if (!roleRow) {
			throw new BizError(t('roleNotExist'));
		}

		await orm(c)
			.update(user)
			.set({ type })
			.where(eq(user.userId, userId))
			.run();

	},

	async setRemark(c, params) {
		const { userId } = params;
		const remark = String(params.remark || '').trim();
		if (remark.length > 200) {
			throw new BizError('Remark cannot exceed 200 characters');
		}
		await orm(c).update(user).set({ remark }).where(eq(user.userId, userId)).run();
	},

	async checkAccountStatus(c, params) {
		const userId = Number(params.userId);
		const userRow = await this.selectByIdIncludeDel(c, userId);
		if (!userRow) {
			throw new BizError('User not found');
		}
		const messages = await orm(c).select().from(email).where(and(
			eq(email.userId, userId),
			eq(email.type, emailConst.type.RECEIVE),
			eq(email.isDel, isDel.NORMAL),
			ne(email.status, emailConst.status.SAVING)
		)).orderBy(desc(email.emailId)).limit(50).all();

		const matchingPlusMessages = messages.filter(message => {
			const text = [message.subject, message.name, message.text, message.content].join('\n').toLowerCase();
			return PLUS_MARKERS.some(marker => text.includes(marker));
		});
		const isDeactivated = messages.some(message => {
			const text = [message.subject, message.name, message.text, message.content].join('\n').toLowerCase();
			return DEACTIVATED_MARKERS.some(marker => text.includes(marker));
		});
		const now = dayjs();
		let planStatus = 'Free';
		let planExpiresAt = null;
		if (matchingPlusMessages.length) {
			const latestReceipt = matchingPlusMessages.reduce((latest, message) =>
				dayjs(message.createTime).isAfter(dayjs(latest.createTime)) ? message : latest
			);
			const expiry = dayjs(latestReceipt.createTime).add(30, 'day');
			if (expiry.isAfter(now)) {
				planStatus = 'Plus';
				planExpiresAt = expiry.format('YYYY-MM-DD HH:mm:ss');
			}
		} else if (userRow.planStatus === 'Plus' && userRow.planExpiresAt && dayjs(userRow.planExpiresAt).isAfter(now)) {
			planStatus = 'Plus';
			planExpiresAt = userRow.planExpiresAt;
		}
		const accountStatus = isDeactivated ? 'Deactivated' : 'Active';
		const accountCheckedAt = now.format('YYYY-MM-DD HH:mm:ss');
		await orm(c).update(user).set({ planStatus, planExpiresAt, accountStatus, accountCheckedAt })
			.where(eq(user.userId, userId)).run();
		return { planStatus, planExpiresAt, accountStatus, accountCheckedAt };
	},

	async updateAccountStatusFromReceivedEmail(c, message) {
		const text = [message.subject, message.name, message.text, message.content].join('\n').toLowerCase();
		const isPlusReceipt = PLUS_MARKERS.some(marker => text.includes(marker));
		const isDeactivated = DEACTIVATED_MARKERS.some(marker => text.includes(marker));
		if (!isPlusReceipt && !isDeactivated) {
			return;
		}
		const userRow = await this.selectByIdIncludeDel(c, message.userId);
		if (!userRow) {
			return;
		}
		const now = dayjs();
		let planStatus = userRow.planStatus || 'Free';
		let planExpiresAt = userRow.planExpiresAt || null;
		if (isPlusReceipt) {
			const expiry = dayjs(message.createTime).add(30, 'day');
			planStatus = expiry.isAfter(now) ? 'Plus' : 'Free';
			planExpiresAt = planStatus === 'Plus' ? expiry.format('YYYY-MM-DD HH:mm:ss') : null;
		}
		await orm(c).update(user).set({
			planStatus,
			planExpiresAt,
			accountStatus: isDeactivated ? 'Deactivated' : (userRow.accountStatus || 'Active'),
			accountCheckedAt: now.format('YYYY-MM-DD HH:mm:ss')
		}).where(eq(user.userId, message.userId)).run();
	},

	async incrUserSendCount(c, quantity, userId) {
		await orm(c).update(user).set({
			sendCount: sql`${user.sendCount}
	  +
	  ${quantity}`
		}).where(eq(user.userId, userId)).run();
	},

	async updateAllUserType(c, type, curType) {
		await orm(c)
			.update(user)
			.set({ type })
			.where(eq(user.type, curType))
			.run();
	},

	async add(c, params) {

		const { email, type, password } = params;

		if (!c.env.domain.includes(emailUtils.getDomain(email))) {
			throw new BizError(t('notEmailDomain'));
		}

		if (password.length < 6) {
			throw new BizError(t('pwdMinLength'));
		}

		const accountRow = await accountService.selectByEmailIncludeDel(c, email);

		if (accountRow && accountRow.isDel === isDel.DELETE) {
			throw new BizError(t('isDelUser'));
		}

		if (accountRow) {
			throw new BizError(t('isRegAccount'));
		}

		const role = roleService.selectById(c, type);

		if (!role) {
			throw new BizError(t('roleNotExist'));
		}

		const { salt, hash } = await saltHashUtils.hashPassword(password);

		const userId = await userService.insert(c, { email, password: hash, salt, type });

		await userService.updateUserInfo(c, userId, true);

		await accountService.insert(c, { userId: userId, email, type, name: emailUtils.getName(email) });
	},

	async resetDaySendCount(c) {
		const roleList = await roleService.selectByIdsAndSendType(c, 'email:send', roleConst.sendType.DAY);
		const roleIds = roleList.map(action => action.roleId);
		await orm(c).update(user).set({ sendCount: 0 }).where(inArray(user.type, roleIds)).run();
	},

	async resetSendCount(c, params) {
		await orm(c).update(user).set({ sendCount: 0 }).where(eq(user.userId, params.userId)).run();
	},

	async restore(c, params) {
		const { userId, type } = params
		await orm(c)
			.update(user)
			.set({ isDel: isDel.NORMAL })
			.where(eq(user.userId, userId))
			.run();
		const userRow = await this.selectById(c, userId);
		await accountService.restoreByEmail(c, userRow.email);

		if (type) {
			await emailService.restoreByUserId(c, userId);
			await accountService.restoreByUserId(c, userId);
		}

	},

	listByRegKeyId(c, regKeyId) {
		return orm(c)
			.select({email: user.email,createTime: user.createTime})
			.from(user)
			.where(eq(user.regKeyId, regKeyId))
			.orderBy(desc(user.userId))
			.all();
	}
};

export default userService;
