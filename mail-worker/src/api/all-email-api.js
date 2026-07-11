import app from '../hono/hono';
import emailService from '../service/email-service';
import result from '../model/result';
import BizError from '../error/biz-error';

app.get('/allEmail/list', async (c) => {
	const data = await emailService.allList(c, c.req.query());
	return c.json(result.ok(data));
})

app.get('/allEmail/mailbox', async (c) => {
	if (c.get('user').email !== c.env.admin) {
		throw new BizError('Administrator access required', 403);
	}
	const data = await emailService.exactMailboxList(c, c.req.query());
	return c.json(result.ok(data));
})

app.delete('/allEmail/delete', async (c) => {
	const list = await emailService.physicsDelete(c, c.req.query());
	return c.json(result.ok(list));
})

app.delete('/allEmail/batchDelete', async (c) => {
	await emailService.batchDelete(c, c.req.query());
	return c.json(result.ok());
})

app.get('/allEmail/latest', async (c) => {
	const list = await emailService.allEmailLatest(c, c.req.query());
	return c.json(result.ok(list));
})
