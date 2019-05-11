#include <linux/v4l2-subdev.h>
#include <linux/b52_api.h>
#include "MediaLib.h"

int MediaLibFindSource(struct PlatCam *cam);
int MediaLibFindPath(struct PlatCam *cam);
int MediaLibFindDst(struct PlatCam *cam);

static char *b52_path_name[] = {
	B52_PATH_YUV_1_NAME,
	B52_PATH_RAW_1_NAME,
	B52_PATH_M2M_1_NAME,
	B52_PATH_YUV_2_NAME,
	B52_PATH_RAW_2_NAME,
	B52_PATH_M2M_2_NAME,
	"b52isd-HighSpeed",
	"b52isd-HDRProcess",
	"b52isd-3DStereo",
	"ccic-dma #0",
	"ccic-dma #1",
};

#if 0
int CamLinkUnitApply(struct CamNode *node, struct CamLinkUnit *unit, int flag)
{
	int ret;

	switch (unit->type) {
	case CAM_LINK_MEDIAENT:
		ret = media_setup_link(node->me->media, unit->mlink->source, unit->mlink->sink, flag);
		break;
	case CAM_LINK_INTERNAL:
		ret = node->ops->SetLink(node, unit->ilink, flag);
		break;
	default:
		app_info("unknow type of LinkUnit: %d", unit->type);
	}
	return ret;
}
#endif
int CamLinkApply(struct CamNode *node, struct CamLink *link, int flag)
{
	int ret = 0;

	if (flag == 0)
		goto link_off;
	if (link->RefCnt == 0) {
		ret = media_setup_link(node->me->media, link->mlink->source, link->mlink->sink, flag);
		if (ret < 0) {
			app_err("failed to enable link '%s => %s': %s",
				link->mlink->source->entity->info.name,
				link->mlink->sink->entity->info.name,
				strerror(errno));
			goto disable;
		}
	}
	link->RefCnt++;
	return 0;

link_off:
	link->RefCnt--;
	if (link->RefCnt == 0) {
disable:
		ret = media_setup_link(node->me->media, link->mlink->source, link->mlink->sink, flag);
		if (ret < 0)
			app_err("failed to disable link '%s => %s': %s",
				link->mlink->source->entity->info.name,
				link->mlink->sink->entity->info.name,
				strerror(errno));
	}
	return ret;
}

int CamRouteApply(struct CamNode *node, struct CamRoute *route, int flag)
{
	int ret = 0;

	if (flag == 0)
		goto route_cut;

	if (route->RefCnt == 0) {
		ret = CamLinkApply(node, route->head, flag);
		if (ret < 0) {
			app_err("failed to enable route '%s => %s': %s",
				route->src->me->info.name,
				route->dst->me->info.name,
				strerror(errno));
			goto disable;
		}
		if (route->more) {
			ret = CamRouteApply(route->head->dst, route->more, flag);
			if (ret < 0)
				goto disable;
		}
	}
	route->RefCnt++;
	return 0;

route_cut:
	route->RefCnt--;

	if (route->RefCnt <= 0) {
		if (route->more) {
			ret = CamRouteApply(route->head->dst, route->more, flag);
			if (ret < 0)
				return ret;
		}
disable:
		ret = CamLinkApply(node, route->head, flag);
		if (ret < 0) {
			app_err("failed to disable route '%s => %s': %s",
				route->src->me->info.name,
				route->dst->me->info.name,
				strerror(errno));
			return ret;
		}
	}
	return 0;
}

struct CamNode *CamNodeCreate(struct PlatCam *plat, struct media_entity *me, int id)
{
	struct CamNode *node = calloc(1, sizeof(*node));

	if (node == NULL)
		return NULL;

	node->plat = plat;
	node->me = me;
	node->id = id;
	SetContainer(me, node);
	strcpy(node->name, me->info.name);
	return node;
}

void CamNodeDestroy(struct CamNode *node)
{
	free(node);
}

static int CamNodeAddLink(struct CamNode *node, struct media_link *mlink,
			struct CamNode *src, struct CamNode *dst)
{
	struct CamLink *link = calloc(1, sizeof(*link));
	if (link == NULL)
		return -ENOMEM;
	link->mlink = mlink;
	link->src = src;
	link->dst = dst;

	node->link = realloc(node->link, (node->NrLink + 1) * sizeof(*node->link));
	node->link[node->NrLink] = link;
	node->NrLink++;
	return 0;
}

int CamNodeSetup(struct CamNode *node)
{
	unsigned int i;
	int ret = 0;

	if (node->NrLink)
		return 0;
	for (i = 0; i < node->me->num_links; i++) {
		struct media_link *link = &node->me->links[i];
		ret = CamNodeAddLink(node, &node->me->links[i],
					GetContainer(link->source->entity),
					GetContainer(link->sink->entity));
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int CamNodeAddRoute(struct CamNode *node, struct CamLink *head, struct CamRoute *more)
{
	if (head->src != node)
		return -EINVAL;
	if (more && (head->dst != more->src))
		return -EINVAL;

	struct CamRoute *route = calloc(1, sizeof(*route));
	if (route == NULL)
		return -ENOMEM;
	route->head = head;
	route->more = more;
	route->src = node;
	route->dst = (more) ? more->dst : head->dst;

	node->route = realloc(node->route, (node->NrRoute + 1) * sizeof(*node->route));
	node->route[node->NrRoute] = route;
	node->NrRoute++;
	return 0;
}

static int CamNodeOpen(struct CamNode *node)
{
	if (node->OpenCnt == 0) {
		node->me->fd = open(node->me->devname, O_RDWR | O_NONBLOCK);
		if (node->me->fd < 0) {
			app_err("MediaLib failed to open entity '%s': %s", node->me->devname, strerror(errno));
			return -errno;
		}
	}
	node->OpenCnt++;
	return node->me->fd;
}

static int CamNodeClose(struct CamNode *node)
{
	node->OpenCnt--;
	if (node->OpenCnt == 0) {
		close(node->me->fd);
		node->me->fd = -1;
	}
	return 0;
}

static int CamNodeSetCombo(struct CamNode *node, struct CamNodeFmtCombo *combo)
{
	int i, ret = 0, fd;

	fd = CamNodeOpen(node);
	if (fd < 0)
		return fd;
	if(combo == NULL) /* coverity issue : 30957 */
		return -1;

	/* Apply selection don't need to notify downstream node */
	if (combo->scope & (1 << PARAM_APPLY_CROP)) {
		struct v4l2_subdev_selection sel = {
			.which	= combo->which,
			.pad	= combo->pad,
			.r	= combo->CropWnd,
		};
		ret = ioctl(node->me->fd, VIDIOC_SUBDEV_S_SELECTION, &sel);
		if (ret < 0) {
			app_err("MediaLib failed to set selection '%s': %s", node->me->devname, strerror(errno));
			goto exit;
		}
		combo->CropWnd = sel.r;
	}

	/* Apply output format, need to notify downstream node */
	if (combo->scope & (1 << PARAM_APPLY_FMT)) {
		/* Try on local first */
		struct v4l2_subdev_format fmt = {
			.pad	= combo->pad,
			.which	= combo->which,
			.format = {
				.width	= combo->width,
				.height	= combo->height,
				.code	= combo->code,
			},
		};
		ret = ioctl(node->me->fd, VIDIOC_SUBDEV_S_FMT, &fmt);
		if (ret < 0) {
			app_err("MediaLib failed to set format '%s': %s", node->me->devname, strerror(errno));
			ret = -errno;
			goto exit;
		}
		combo->width = fmt.format.width;
		combo->height = fmt.format.height;
		combo->code = fmt.format.code;

		/* only sync format with downstream subdev */
		if (node->me->pads[combo->pad].flags & MEDIA_PAD_FL_SINK)
			goto done;

		/* For each downstream node, apply */
		for (i = 0; i < node->NrLink; i++) {
			struct CamLink *link = node->link[i];
			if ((link->src != node) || (link->mlink->source->index != combo->pad))
				continue;
			if (link->RefCnt == 0)
				continue;
			struct CamNodeFmtCombo r_combo = *combo;
			r_combo.pad = link->mlink->sink->index;
			r_combo.scope = (1 << PARAM_APPLY_FMT);
			ret = CamNodeSetCombo(GetContainer(link->dst->me), &r_combo);
			if (ret < 0)
				goto exit;
			if ((r_combo.width != combo->width) ||
				(r_combo.height != combo->height) ||
				(r_combo.code != combo->code)) {
				app_err("new format<w%d, h%d, c%X> proposed by subdev %s, original format is <w%d, h%d, c%X>",
					r_combo.width, r_combo.height, r_combo.code, link->dst->me->info.name,
					combo->width, combo->height, combo->code);
				goto exit;
			}
		}
done:
		;
	}
exit:
	CamNodeClose(node);
	return ret;
}

static int CamNodeGetCombo(struct CamNode *node, struct CamNodeFmtCombo *combo)
{
	int ret = 0, fd;

	fd = CamNodeOpen(node);
	if (fd < 0)
		return fd;
	if(combo == NULL) /* coverity issue : 30957 */
		return -1;

	if (combo->scope & (1 << PARAM_APPLY_CROP)) {
		struct v4l2_subdev_selection sel = {
			.which	= combo->which,
			.pad	= combo->pad,
		};
		ret = ioctl(node->me->fd, VIDIOC_SUBDEV_G_SELECTION, &sel);
		if (ret < 0) {
			app_err("MediaLib failed to get selection '%s': %s", node->me->devname, strerror(errno));
			ret = -errno;
			goto exit;
		}
		combo->CropWnd = sel.r;
	}

	/* Apply output format, need to notify downstream node */
	if (combo->scope & (1 << PARAM_APPLY_FMT)) {
		/* Try on local first */
		struct v4l2_subdev_format fmt = {
			.pad	= combo->pad,
			.which	= combo->which,
		};
		ret = ioctl(node->me->fd, VIDIOC_SUBDEV_G_FMT, &fmt);
		if (ret < 0) {
			app_err("MediaLib failed to get format '%s': %s", node->me->devname, strerror(errno));
			ret = -errno;
			goto exit;
		}
		combo->width = fmt.format.width;
		combo->height = fmt.format.height;
		combo->code = fmt.format.code;
	}
exit:
	CamNodeClose(node);
	return ret;
}

static int CamNodeSetCtrl(struct CamNode *node, struct CamCtx *ctx)
{
	int i, ret = 0, fd;

	fd = CamNodeOpen(node);
	if (fd < 0)
		return fd;

	ret = ioctl(fd, VIDIOC_PRIVATE_B52ISP_TOPOLOGY_SNAPSHOT, ctx);
	if (ret < 0) {
		app_err("MediaLib failed to trigger topology snapshot for context '%s' => '%s': %s", ctx->src->name, ctx->path->name, strerror(errno));
		ret = -errno;
		goto exit;
	}

exit:
	CamNodeClose(node);
	return ret;
}

/* supporting queue algorithm for Route Search */
#define NODE_QUEUE_DEPTH	20
struct NodeQ {
	struct CamNode *queue[NODE_QUEUE_DEPTH];
	int	out;
	int	in;
} __CamNodeQ;

static bool NodeQEmpty(struct NodeQ *q)
{
	return q->in == q->out;
}

static void NodeQReset(struct NodeQ *q)
{
	q->in = q->out = 0;
}

static int NodeQPush(struct NodeQ *q, struct CamNode *node)
{
	int pos = q->in + 1;
	if (pos >= NODE_QUEUE_DEPTH)
		pos = 0;
	/* Queue full? */
	if (pos == q->out)
		return -ENOMEM;

	q->queue[q->in] = node;
	q->in = pos;
	return 0;
}

static struct CamNode *NodeQPop(struct NodeQ *q)
{
	int pos = q->out + 1;
	struct CamNode *node = q->queue[q->out];
	if (pos >= NODE_QUEUE_DEPTH)
		pos = 0;
	if (NodeQEmpty(q))
		return NULL;

	q->out = pos;
	return node;
}
#define QEmpty NodeQEmpty(&__CamNodeQ)
#define QReset NodeQReset(&__CamNodeQ)
#define QPush(n) NodeQPush(&__CamNodeQ, (n))
#define QPop NodeQPop(&__CamNodeQ)

static int CamNodeSetupRoute(struct CamNode *node)
{
	int i, j, ret;
	if (node->NrRoute)
		return node->NrRoute;

	for (i = 0; i < node->NrLink; i++) {
		struct CamNode *dst = node->link[i]->dst;
		if ((dst == NULL) || (dst == node))
			continue;
		if (dst->level) {
			ret = CamNodeSetupRoute(dst);
			if (ret < 0)
				return ret;
			for (j = 0; j < dst->NrRoute; j++) {
				ret = CamNodeAddRoute(node, node->link[i], dst->route[j]);
				if (ret < 0) {
					app_err("failed to add route '%s'==>'%s'", node->name, dst->name);
					return ret;
				}
			}
		} else {
			ret = CamNodeAddRoute(node, node->link[i], NULL);
			if (ret < 0) {
				app_err("failed to add route '%s'=>'%s'", node->name, dst->name);
				return ret;
			}
		}
	}
#if 0
	for (i = 0; i < node->NrRoute; i++)
		app_info("route '%s' ==> '%s' detected", node->route[i]->src->name, node->route[i]->dst->name);
#endif
	return node->NrRoute;
}
/* Use DynamicPrograming to setup Source for reachable Path */
static int MediaLibSearchRoute(struct PlatCam *cam)
{
	struct media_entity *next;
	int i, j, ret = 0;

	QReset;
	for (i = 0; i < cam->NrPath; i++) {
		if (cam->PathPool[i]) {
			ret = QPush(cam->PathPool[i]);
			if (ret < 0)
				goto exit_err;
		}
	}
	do {
		struct CamNode *node = QPop;
		if (node == NULL)
			break;
		for (j = 0; j < node->NrLink; j++) {
			struct CamNode *up = node->link[j]->src;
			if (up == node)
				continue;
			if (node->level + 1 > up->level) {
				up->level =  node->level + 1;
				ret = QPush(up);
				if (ret < 0)
					goto exit_err;
			}
		}
	} while(1);
	for (i = 0; i < cam->NrSrc; i++) {
		ret = CamNodeSetupRoute(cam->SrcPool[i]);
		if (ret < 0)
			goto exit_err;
	}

	QReset;
	for (i = 0; i < cam->NrDst; i++) {
		if (cam->DstPool[i]) {
			ret = QPush(cam->DstPool[i]);
			if (ret < 0)
				goto exit_err;
		}
	}
	do {
		struct CamNode *node = QPop;
		if (node == NULL)
			break;
		for (j = 0; j < node->NrLink; j++) {
			struct CamNode *up = node->link[j]->src;
			if (up == node)
				continue;
			if (node->level + 1 > up->level) {
				up->level =  node->level + 1;
				ret = QPush(up);
				if (ret < 0)
					goto exit_err;
			}
		}
	} while(1);
	for (i = 0; i < cam->NrPath; i++) {
		ret = CamNodeSetupRoute(cam->PathPool[i]);
		if (ret < 0)
			goto exit_err;
	}

	QReset;
	return 0;

exit_err:
	QReset;
	return ret;
}


struct PlatCam *MediaLibInit()
{
	struct PlatCam *cam;
	int i, j, ret;

	cam = calloc(1, sizeof(struct PlatCam));
	if (cam == NULL)
		return NULL;

	cam->media = media_open("/dev/media0");
	if (cam->media == NULL) {
		app_err("Failed to open media node");
		goto out;
	}

	/* Create Node for each media_entity */
	for (i = 0; i < ME_CNT; i++) {
		struct media_entity *me = media_get_entity_by_id(cam->media, i | MEDIA_ENT_ID_FLAG_NEXT);
		struct CamNode *node;
		if (me == NULL)
			break;
		node = CamNodeCreate(cam, me, i);
		if (node == NULL)
			goto out;

		node->id = i;
		cam->node[i] = node;
		cam->NrME++;
	}

	/* Setup each node for the dst and links */
	for (i = 0; i < cam->NrME; i++) {
		if (cam->node[i]) {
			ret = CamNodeSetup(cam->node[i]);
			if (ret < 0)
				goto out;
#if 0
	int j;
	for (j = 0; j < cam->node[i]->NrLink; j++) {
		struct CamLink *link = cam->node[i]->link[j];
			app_info("%s link%d: '%s'=>'%s'", cam->node[i]->name, j, link->src->name, link->dst->name);
	}
#endif
		}
	}

	/* Identify Source, Path, Output among all Nodes */
	ret = MediaLibFindSource(cam);
	if (ret < 0)
		goto out;

	ret = MediaLibFindPath(cam);
	if (ret < 0)
		goto out;

	ret = MediaLibFindDst(cam);
	if (ret < 0)
		goto out;

	ret = MediaLibSearchRoute(cam);
	if (ret < 0)
		goto out;
	/* This is just a W/R to retain power status */
	{
		int sid;
		struct media_entity *me;
		struct CamNode *node;

		/* retain ISP power */
		me = media_get_entity_by_name(cam->media, B52_IDI1_NAME, strlen(B52_IDI1_NAME));
		if (me == NULL) {
			ret = -ENODEV;
			goto out;
		}
		node = GetContainer(me);
		if (node == NULL) {
			ret = -ENODEV;
			goto out;
		}
		CamNodeOpen(node);

		/* retain sensor power */
		/*for (sid = 0; sid < cam->NrSrc; sid++) {
			node = cam->SrcPool[sid];
			if (!TstFlag(node, CAMNODE_FL_T_SOURCE))
				continue;
			CamNodeOpen(node);
		}*/
	}
	return cam;

out:
	MediaLibExit(cam);
	app_err("Failed to initialize media-lib");
	return NULL;
}

void OpenCam(struct PlatCam *cam, int srcID)
{
	struct CamNode *node;

	node = cam->SrcPool[srcID];
	CamNodeOpen(node);
	return;
}

void CloseCam(struct PlatCam *cam, int srcID)
{
	struct CamNode *node;

	node = cam->SrcPool[srcID];
	CamNodeClose(node);
	return;
}


void MediaLibExit(struct PlatCam *cam)
{
	/* This is just a W/R to relax power status */
	{
		int sid;
		struct media_entity *me;
		struct CamNode *node;

		/* relax sensor power */
		/*for (sid = 0; sid < cam->NrSrc; sid++) {
			node = cam->SrcPool[sid];
			if (!TstFlag(node, CAMNODE_FL_T_SOURCE))
				continue;
			CamNodeClose(node);
		}*/

		/* relax ISP power */
		me = media_get_entity_by_name(cam->media, B52_IDI1_NAME, strlen(B52_IDI1_NAME));
		if (me) {
			node = GetContainer(me);
			if (node)
				CamNodeClose(node);
		}
	}

	if (cam->media)
		media_close(cam->media);
	free(cam);
}

int MediaLibFindSource(struct PlatCam *cam)
{
	int i, j;

	for (i = 0; i < cam->NrME; i++) {
		struct media_entity *me;
		if (cam->node[i] == NULL)
			continue;
		me = cam->node[i]->me;
		if (me == NULL)
			continue;
		if ((me->info.type != MEDIA_ENT_T_V4L2_SUBDEV_SENSOR) &&
			(me->info.type != MEDIA_ENT_T_DEVNODE_V4L))
			continue;
		/* Make sure it's really a source entity, and don't accept data */
		for (j = 0; j < me->info.pads; j++) {
			struct media_pad *pad = me->pads + j;
			if (pad->flags & MEDIA_PAD_FL_SINK)
				goto skip;
		}
		if (me->info.type == MEDIA_ENT_T_DEVNODE_V4L) {
			SetFlag(cam->node[i], CAMNODE_FL_T_INPUT);
			app_info("Find input %d <v4l-dev>: %s", cam->NrSrc, cam->node[i]->name);
		} else {
			SetFlag(cam->node[i], CAMNODE_FL_T_SOURCE);
			app_info("Find input %d <sensor>: %s", cam->NrSrc, cam->node[i]->name);
		}
		cam->SrcPool[cam->NrSrc] = cam->node[i];
		cam->NrSrc++;
skip:;
	}
#if 0
	/* FIXME: remove the hard coding!!! */
	for (i = ME_CCIC_CSI0; i <= ME_CCIC_CSI1; i++ ) {
		if (cam->node[i]->me == NULL)
			continue;
		cam->SrcPool[cam->NrSrc] = cam->node[i];
		cam->NrSrc++;
	}
#endif
	return cam->NrSrc;
}

int MediaLibFindPath(struct PlatCam *cam)
{
	unsigned int i, ret;

	for (i = 0; i < sizeof(b52_path_name)/sizeof(b52_path_name[0]); i++) {
		struct media_entity *me = media_get_entity_by_name(cam->media, b52_path_name[i], strlen(b52_path_name[i]));
		struct CamNode *node;
		if (me == NULL)
			continue;
		node = GetContainer(me);
		if (node == NULL)
			continue;
		SetFlag(node, CAMNODE_FL_T_PATH);
		app_info("Find path %d: %s", cam->NrPath, node->name);
		cam->PathPool[cam->NrPath] = node;
		cam->NrPath++;
	}
	return cam->NrPath;
}

int MediaLibFindDst(struct PlatCam *cam)
{
	int i, j;

	for (i = 0; i < cam->NrME; i++) {
		struct media_entity *me;
		if (cam->node[i] == NULL)
			continue;
		me = cam->node[i]->me;
		if ((me == NULL) || (me->info.type != MEDIA_ENT_T_DEVNODE_V4L))
			continue;
		for (j = 0; j < me->info.pads; j++) {
			struct media_pad *pad = me->pads + j;
			if (pad->flags & MEDIA_PAD_FL_SOURCE)
				goto skip;
		}
		app_info("Find output %d: %s", cam->NrDst, cam->node[i]->name);
		SetFlag(cam->node[i], CAMNODE_FL_T_OUTPUT);
		cam->DstPool[cam->NrDst] = cam->node[i];
		cam->NrDst++;
skip:;
	}
	return cam->NrDst;
}

int MediaLibEnumSource(struct PlatCam *cam, int idx, struct CamNodeEnum *desc)
{
	int i, j, cnt = -1;

	if (cam == NULL)
		return -EINVAL;
	if (idx >= cam->NrSrc)
		return -ENODEV;

	desc->index = idx;
	strncpy(desc->name, cam->SrcPool[idx]->name, sizeof(desc->name));
	desc->name[sizeof(desc->name)-1] = '\0';
	desc->route = cam->SrcPool[idx]->route;
	desc->NrRoute = cam->SrcPool[idx]->NrRoute;
	return 0;
}

int MediaLibEnumPath(struct PlatCam *cam, int idx, struct CamNodeEnum *desc)
{
	if (cam == NULL)
		return -EINVAL;
	if (idx >= cam->NrPath)
		return -ENODEV;

	desc->index = idx;
	strncpy(desc->name, cam->PathPool[idx]->name, sizeof(desc->name));
	desc->name[sizeof(desc->name)-1] = '\0';
	desc->route = cam->PathPool[idx]->route;
	desc->NrRoute = cam->PathPool[idx]->NrRoute;
	return 0;
}

int CameraContextInit(struct PlatCam *cam, int SrcID, int PathID, int NrDst)
{
	struct CamNode *s_node, *p_node;
	struct CamCtx *ctx;
	struct CamRoute *route;
	int ctx_id, i, j, ret = -1;

	if (SrcID >= cam->NrSrc)
		return -EINVAL;

	if (PathID >= cam->NrPath)
		return -EINVAL;

	p_node = cam->PathPool[PathID];
	if (NrDst > p_node->NrRoute)
		return -EPERM;

	for (i = 0; i < cam->SrcPool[SrcID]->NrRoute; i++) {
		if (cam->SrcPool[SrcID]->route[i]->dst == p_node)
			goto find;
	}
	app_err("NO route find between '%s' and '%s'", cam->SrcPool[SrcID]->name, cam->PathPool[PathID]->name);
	return -EPIPE;

find:
	route = cam->SrcPool[SrcID]->route[i];
	for (i = 0; i < CONTEXT_PER_PLATFORM; i++) {
		if (cam->ctx[i])
			continue;
		ctx = calloc(1, sizeof(struct CamCtx));
		if (cam->ctx == NULL)
			return -ENOMEM;
		goto ctx_ready;
	}
	app_info("Maximum number of context:%d reached", CONTEXT_PER_PLATFORM);
	return -ENOMEM;
ctx_ready:
	ctx_id = i;
	ctx->route = route;
	ctx->flags = 0;
	ctx->src = route->src;
	ctx->path = route->dst;
	while (route->head->dst != ctx->path)
		route = route->more;
	ctx->crop = route->head->src;
	/* Static decide output for now, need to figure out a strategy */
	ctx->NrOut = NrDst;
	ctx->out = calloc(NrDst, sizeof(struct CamRoute *));
	for (i = 0, j = -1; i < NrDst; i++) {
		struct CamNode *dst;
		for (j++; j < ctx->path->NrRoute; j++) {
			dst = ctx->path->route[j]->dst;
			/* FIXME: MUST hold a lock before access nodes' flag */
			if (!TstFlag(dst, CAMNODE_FL_S_OCCUPY)) {
				SetFlag(dst, CAMNODE_FL_S_OCCUPY);
				/* FIXME: unlock here */
				break;
			}
			/* FIXME: unlock here */
		}
		if (j >= ctx->path->NrRoute) {
			app_err("can't connect to output %d: no vdev available", i);
			/* release occupied outputs */
			for (j = i - 1; j >= 0; j--) {
				/* FIXME: MUST hold a lock before access nodes' flag */
				ClrFlag(ctx->out[j]->dst, CAMNODE_FL_S_OCCUPY);
				/* FIXME: unlock here */
			}
			goto exit_err;
		}
		ctx->out[i] = ctx->path->route[j];
	}

	/* Now really apply the links */
	ret = CamRouteApply(ctx->route->src, ctx->route, 1);
	if (ret < 0)
		goto exit_err;
	for (i = 0; i < ctx->NrOut; i++) {
		ret = CamRouteApply(ctx->path, ctx->out[i], 1);
		if (ret < 0)
			goto exit_err;
	}

	SetFlag(ctx, CAMCTX_FL_INIT);
	cam->ctx[ctx_id] = ctx;

	app_info("context%d [source'%s' => crop'%s' => path'%s' => %d outputs] created", ctx_id, ctx->src->name, ctx->crop->name, ctx->path->name, NrDst);
	return ctx_id;

exit_err:
	cam->ctx[ctx_id] = NULL;
	free(ctx);
	return ret;
}

int CameraContextPara(struct PlatCam *cam, int CtxID, struct CamCtxParam *ParamList, int NrParam)
{
	struct CamCtx *ctx;
	int i, j, ret = 0;

	if ((cam == NULL) || (CtxID < 0) || (CtxID >= CONTEXT_PER_PLATFORM))
		return -EINVAL;
	ctx = cam->ctx[CtxID];
	if (ctx == NULL)
		return -ENODEV;

	for (i = 0; i < NrParam; i++) {
		struct CamRoute *route = ctx->route;
		struct CamNode *obj = NULL, *succ = NULL;
		struct CamNodeFmtCombo *combo = NULL;

		/* Find objective node and pad */
		switch (ParamList[i].ParamName) {
		case PARAM_SRC_SET_COMBO:
		case PARAM_SRC_GET_COMBO:
			route = ctx->route;
			obj = ctx->src;
			goto find_pad;
		case PARAM_CROP_SET_COMBO:
		case PARAM_CROP_GET_COMBO:
			route = ctx->route;
			obj = ctx->crop;
			goto find_pad;
		case PARAM_PATH_SET_CROP:
		case PARAM_PATH_GET_CROP:
			/* all outputs are connected to the same pad of path, so take any output branch is OK */
			combo = ParamList[i].ParamArg;
			combo->scope = (1 << PARAM_APPLY_CROP);
			route = ctx->out[0];
			obj = ctx->path;
find_pad:
			/* find successive node, and connecting pad */
			while (route && route->src != obj)
				route = route->more;
			if (!route) {
				app_err("internal error, node %s not find in context", obj->name);
				return -ENODEV;
			}
			succ = route->head->dst;

			for (j = 0; j < obj->NrLink; j++) {
				struct CamLink *link = obj->link[j];
				if ((link->src != obj) || (link->dst != succ))
					continue;
				if (link->RefCnt == 0)
					continue;
				combo = ParamList[i].ParamArg;
				combo->pad = link->mlink->source->index;
				goto apply_cmd;
			}
			app_err("no link find connecting %s and %s", obj->name, succ->name);
			break;
		default:
			app_err("unknown parameter name: %d", ParamList[i].ParamName);
		}
apply_cmd:
		switch (ParamList[i].ParamName) {
		case PARAM_SRC_SET_COMBO:
		case PARAM_CROP_SET_COMBO:
		case PARAM_PATH_SET_CROP:
			ret = CamNodeSetCombo(obj, combo);
			if (ret < 0)
				goto exit;
		case PARAM_SRC_GET_COMBO:
		case PARAM_CROP_GET_COMBO:
		case PARAM_PATH_GET_CROP:
			ret = CamNodeGetCombo(obj, combo);
			if (ret < 0)
				goto exit;
		}
	}
	ret = CamNodeSetCtrl(ctx->path, ctx);
exit:
	return ret;
}

int CameraContextKill(struct PlatCam *cam, int CtxID)
{
	struct CamCtx *ctx;
	int i, ret = 0;

	if (CtxID >= CONTEXT_PER_PLATFORM)
		return -EINVAL;
	if (cam->ctx[CtxID] == NULL)
		return 0;
	ctx = cam->ctx[CtxID];

	for (i = 0; i < ctx->NrOut; i++)
		if (TstFlag(ctx, CAMCTX_FL_DST1_BUSY + i)) {
			CameraContextOutputClose(cam, CtxID, i);
			ret = -EBUSY;
			break;
		}
	if (TstFlag(ctx, CAMCTX_FL_INPUT_BUSY)) {
		CameraContextInputClose(cam, CtxID);
		ret = -EBUSY;
	}

	for (i = 0; i < ctx->NrOut; i++)
		ret |= CamRouteApply(ctx->path, ctx->out[i], 0);
	ret |= CamRouteApply(ctx->route->src, ctx->route, 0);

	/* release occupied outputs */
	for (i = ctx->NrOut - 1; i >= 0; i--) {
		/* FIXME: MUST hold a lock before access nodes' flag */
		ClrFlag(ctx->out[i]->dst, CAMNODE_FL_S_OCCUPY);
		/* FIXME: unlock here */
	}

	app_info("context%d [source'%s' => crop'%s' => path'%s' => %d outputs] removed", CtxID, ctx->src->name, ctx->crop->name, ctx->path->name, ctx->NrOut);
	free(ctx->out);
	free(ctx);
	cam->ctx[CtxID] = NULL;
	return ret;
}

int CameraContextOutputOpen(struct PlatCam *cam, int CtxID, int port)
{
	struct CamCtx *ctx;
	struct CamNode *out;

	if (CtxID >= CONTEXT_PER_PLATFORM)
		return -EINVAL;
	if (cam->ctx[CtxID] == NULL)
		return -ENODEV;
	ctx = cam->ctx[CtxID];
	if (port >= ctx->NrOut)
		return -EINVAL;
	out = ctx->out[port]->dst;

	if (out->me->fd >= 0)
		return -EBUSY;
	out->me->fd = open(out->me->devname, O_RDWR | O_NONBLOCK);
	if (out->me->fd < 0) {
		app_err("MediaLib failed to open output '%s': %s", out->me->devname, strerror(errno));
		return -errno;
	}
	SetFlag(ctx, CAMCTX_FL_DST1_BUSY + port);
	return out->me->fd;
}

int CameraContextOutputClose(struct PlatCam *cam, int CtxID, int port)
{
	struct CamCtx *ctx;
	struct CamNode *out;

	if (CtxID >= CONTEXT_PER_PLATFORM)
		return -EINVAL;
	if (cam->ctx[CtxID] == NULL)
		return -ENODEV;
	ctx = cam->ctx[CtxID];
	if (port >= ctx->NrOut)
		return -EINVAL;
	out = ctx->out[port]->dst;

	if (out->me->fd < 0)
		return -EPERM;
	close(out->me->fd);
	out->me->fd = -1;
	ClrFlag(ctx, CAMCTX_FL_DST1_BUSY + port);
	return 0;
}

int CameraContextInputOpen(struct PlatCam *cam, int CtxID)
{
	struct CamCtx *ctx;
	struct CamNode *in;
	int ret;

	if (CtxID >= CONTEXT_PER_PLATFORM)
		return -EINVAL;
	if (cam->ctx[CtxID] == NULL)
		return -ENODEV;
	ctx = cam->ctx[CtxID];
	in = ctx->src;
	if (in->me->info.type != MEDIA_ENT_T_DEVNODE_V4L)
		return -EPERM;

	if (in->me->fd >= 0)
		return -EBUSY;
	in->me->fd = open(in->me->devname, O_RDWR | O_NONBLOCK);
	if (in->me->fd < 0) {
		app_err("MediaLib failed to open input '%s': %s", in->me->devname, strerror(errno));
		return -errno;
	}
	SetFlag(ctx, CAMCTX_FL_INPUT_BUSY);
	return in->me->fd;
}

int CameraContextInputClose(struct PlatCam *cam, int CtxID)
{
	struct CamCtx *ctx;
	struct CamNode *in;

	if (CtxID >= CONTEXT_PER_PLATFORM)
		return -EINVAL;
	if (cam->ctx[CtxID] == NULL)
		return -ENODEV;
	ctx = cam->ctx[CtxID];
	in = ctx->src;
	if (in->me->info.type != MEDIA_ENT_T_DEVNODE_V4L)
		return -EPERM;

	if (in->me->fd < 0)
		return -EPERM;
	close(in->me->fd);
	in->me->fd = -1;
	ClrFlag(ctx, CAMCTX_FL_INPUT_BUSY);
	return 0;
}

int CameraContextPathGet(struct PlatCam *cam, int CtxID)
{
	struct CamNode *path;

	if (CtxID >= CONTEXT_PER_PLATFORM)
		return -EINVAL;
	if (cam->ctx[CtxID] == NULL)
		return -ENODEV;
	path = cam->ctx[CtxID]->path;

	return CamNodeOpen(path);
}

int CameraContextPathPut(struct PlatCam *cam, int CtxID)
{
	if (CtxID >= CONTEXT_PER_PLATFORM)
		return -EINVAL;
	if (cam->ctx[CtxID] == NULL)
		return -ENODEV;

	return CamNodeClose(cam->ctx[CtxID]->path);
}

int CameraContextSourceGet(struct PlatCam *cam, int CtxID)
{
	struct CamNode *src;

	if (CtxID >= CONTEXT_PER_PLATFORM)
		return -EINVAL;
	if (cam->ctx[CtxID] == NULL)
		return -ENODEV;
	src = cam->ctx[CtxID]->src;

	if (src->me->info.type != MEDIA_ENT_T_V4L2_SUBDEV_SENSOR)
		return -EPERM;

	return CamNodeOpen(src);
}

int CameraContextSourcePut(struct PlatCam *cam, int CtxID)
{
	if (CtxID >= CONTEXT_PER_PLATFORM)
		return -EINVAL;
	if (cam->ctx[CtxID] == NULL)
		return -ENODEV;

	return CamNodeClose(cam->ctx[CtxID]->src);
}
