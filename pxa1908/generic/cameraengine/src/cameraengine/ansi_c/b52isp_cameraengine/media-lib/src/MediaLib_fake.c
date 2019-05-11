#include <linux/v4l2-subdev.h>
#include "MediaLib.h"

static char *socisp_me_name[ME_CNT] = {
	[ME_CCIC_CSI0]	= "ccic-csi #0",
	[ME_CCIC_CSI1]	= "ccic-csi #1",
	[ME_CCIC_DMA0]	= "ccic-dma #0",
	[ME_CCIC_DMA1]	= "ccic-dma #1",
	[ME_ISP_IDI]	= "b52isd-IDI",
	[ME_ISP_PIPE1]	= "b52isd-Pipeline#1",
	[ME_ISP_DUMP1]	= "b52isd-DataDump#1",
	[ME_ISP_PIPE2]	= "b52isd-Pipeline#2",
	[ME_ISP_DUMP2]	= "b52isd-DataDump#2",
	[ME_ISP_HS]	= "b52isd-HighSpeed",
	[ME_ISP_HDR]	= "b52isd-HDRProcess",
	[ME_ISP_3D]	= "b52isd-3DStereo",
	[ME_ISP_A1W1]	= "b52isd-AXI1-write1",
	[ME_ISP_A1W2]	= "b52isd-AXI1-write2",
	[ME_ISP_A1R1]	= "b52isd-AXI1-read1",
	[ME_ISP_A2W1]	= "b52isd-AXI2-write1",
	[ME_ISP_A2W2]	= "b52isd-AXI2-write2",
	[ME_ISP_A2R1]	= "b52isd-AXI2-read1",
	[ME_ISP_A3W1]	= "b52isd-AXI3-write1",
	[ME_ISP_A3W2]	= "b52isd-AXI3-write2",
	[ME_ISP_A3R1]	= "b52isd-AXI3-read1",
	[ME_VDEV_CCIC0] = "vout<ccic-dma #0>",
	[ME_VDEV_CCIC1] = "vout<ccic-dma #1>",
	[ME_VDEV_A1W1]	= "vout<b52isd-AXI1-write1>",
	[ME_VDEV_A1W2]	= "vout<b52isd-AXI1-write2>",
	[ME_VDEV_A1R1]	= "vin<b52isd-AXI1-read1>",
	[ME_VDEV_A2W1]	= "vout<b52isd-AXI2-write1>",
	[ME_VDEV_A2W2]	= "vout<b52isd-AXI2-write2>",
	[ME_VDEV_A2R1]	= "vin<b52isd-AXI2-read1>",
	[ME_VDEV_A3W1]	= "vout<b52isd-AXI3-write1>",
	[ME_VDEV_A3W2]	= "vout<b52isd-AXI3-write2>",
	[ME_VDEV_A3R1]	= "vin<b52isd-AXI3-read1>",
	[ME_SENSOR_OV5642]	= "ovt.ov5642",
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
			return errno;
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
			ret = errno;
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
	int ret, fd;

	fd = CamNodeOpen(node);
	if (fd < 0)
		return fd;

	if (combo->scope & (1 << PARAM_APPLY_CROP)) {
		struct v4l2_subdev_selection sel = {
			.which	= combo->which,
			.pad	= combo->pad,
		};
		ret = ioctl(node->me->fd, VIDIOC_SUBDEV_G_SELECTION, &sel);
		if (ret < 0) {
			app_err("MediaLib failed to get selection '%s': %s", node->me->devname, strerror(errno));
			ret = errno;
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
			ret = errno;
			goto exit;
		}
		combo->width = fmt.format.width;
		combo->height = fmt.format.height;
		combo->code = fmt.format.code;
	}
exit:
	CamNodeClose(node);
	return 0;
}

static int CamNodeSetFmt(struct CamNode *node, struct CamNodeFmtCombo *combo)
{
	combo->scope = (1 << PARAM_APPLY_FMT);
	return CamNodeSetCombo(node, combo);
}

static int CamNodeGetFmt(struct CamNode *node, struct CamNodeFmtCombo *combo)
{
	combo->scope = (1 << PARAM_APPLY_FMT);
	return CamNodeGetCombo(node, combo);
}

static int CamNodeSetCrop(struct CamNode *node, struct CamNodeFmtCombo *combo)
{
	combo->scope = (1 << PARAM_APPLY_CROP);
	return CamNodeSetCombo(node, combo);
}

static int CamNodeGetCrop(struct CamNode *node, struct CamNodeFmtCombo *combo)
{
	combo->scope = (1 << PARAM_APPLY_CROP);
	return CamNodeGetCombo(node, combo);
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
		ret = errno;
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
		if (dst == node)
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
#if 0
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
		struct media_entity *me = media_get_entity_by_name(cam->media, socisp_me_name[i], strlen(socisp_me_name[i]));
		struct CamNode *node;
		if (me == NULL)
			continue;
		node = CamNodeCreate(cam, me, i);
		if (node == NULL)
			goto out;

		node->id = i;
		cam->node[i] = node;
	}

	/* Setup each node for the dst and links */
	for (i = 0; i < ME_CNT; i++) {
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

	return cam;

out:
	MediaLibExit(cam);
	app_err("Failed to initialize media-lib");
	return NULL;
#else
	cam = calloc(1, sizeof(struct PlatCam));

	return cam;
#endif
}

void MediaLibExit(struct PlatCam *cam)
{
#if 0
	if (cam->isp)
		b52isp_close(cam->isp);
	if (cam->media)
		media_close(cam->media);
	free(cam);
#else
	free(cam);
#endif
}

int MediaLibFindSource(struct PlatCam *cam)
{
	int i, j;

	for (i = 0; i < ME_CNT; i++) {
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
		if (me->info.type == MEDIA_ENT_T_DEVNODE_V4L)
			SetFlag(cam->node[i], CAMNODE_FL_T_INPUT);
		else
			SetFlag(cam->node[i], CAMNODE_FL_T_SOURCE);
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
	int i, ret;

	for (i = ME_ISP_PIPE1; i <= ME_ISP_3D; i++) {
		if (cam->node[i] == NULL || cam->node[i]->me == NULL)
			continue;
		SetFlag(cam->node[i], CAMNODE_FL_T_PATH);
		cam->PathPool[cam->NrPath] = cam->node[i];
		cam->NrPath++;
	}

	for (i = ME_CCIC_DMA0; i <= ME_CCIC_DMA1; i++ ) {
		if (cam->node[i] == NULL || cam->node[i]->me == NULL)
			continue;
		SetFlag(cam->node[i], CAMNODE_FL_T_PATH);
		cam->PathPool[cam->NrPath] = cam->node[i];
		cam->NrPath++;
	}
	return cam->NrPath;
}

int MediaLibFindDst(struct PlatCam *cam)
{
	int i, j;

	for (i = 0; i < ME_CNT; i++) {
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
		SetFlag(cam->node[i], CAMNODE_FL_T_OUTPUT);
		cam->DstPool[cam->NrDst] = cam->node[i];
		cam->NrDst++;
skip:;
	}
	return cam->NrDst;
}

int MediaLibEnumSource(struct PlatCam *cam, int idx, struct CamNodeEnum *desc)
{
#if 0
	int i, j, cnt = -1;

	if (cam == NULL)
		return -EINVAL;
	if (idx >= cam->NrSrc)
		return -ENODEV;

	desc->index = cam->SrcPool[idx]->id;
	strncpy(desc->name, cam->SrcPool[idx]->name, sizeof(desc->name));
	desc->route = cam->SrcPool[idx]->route;
	desc->NrRoute = cam->SrcPool[idx]->NrRoute;
	return 0;
#else
	if ( idx >= 2 )
	{
		return -ENODEV;
	}

	desc->index = idx;

	if ( idx == 0 )
	{
		strcpy( desc->name, "ov13850" );
	}
	else if ( idx == 1 )
	{
		strcpy( desc->name, "ov5642" );
	}

	return 0;
#endif
}

int MediaLibEnumPath(struct PlatCam *cam, int idx, struct CamNodeEnum *desc)
{
#if 0
	if (cam == NULL)
		return -EINVAL;
	if (idx >= cam->NrPath)
		return -ENODEV;

	desc->index = cam->PathPool[idx]->id;
	strncpy(desc->name, cam->PathPool[idx]->name, sizeof(desc->name));
	desc->route = cam->PathPool[idx]->route;
	desc->NrRoute = cam->PathPool[idx]->NrRoute;
	return 0;
#else
	if ( idx >= 4 )
	{
		return -ENODEV;
	}

	desc->index = idx;

	if ( idx == 0 )
	{
		strcpy( desc->name, "b52isd-Pipeline#1" );
	}
	if ( idx == 1 )
	{
		strcpy( desc->name, "b52isd-Pipeline#2" );
	}
	if ( idx == 2 )
	{
		strcpy( desc->name, "b52isd-HighSpeed" );
	}
	if ( idx == 3 )
	{
		strcpy( desc->name, "b52isd-DataDump#1" );
	}
	return 0;
#endif
}

int CameraContextInit(struct PlatCam *cam, int SrcID, int PathID, int NrDst)
{
#if 0
	struct CamNode *s_node, *p_node;
	struct CamCtx *ctx;
	struct CamRoute *route;
	int ctx_id, i, ret;

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
	for (i = 0; i < NrDst; i++)
		ctx->out[i] = ctx->path->route[i];

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
#else
	return 0;
#endif
}

int CameraContextPara(struct PlatCam *cam, int CtxID, struct CamCtxParam *ParamList, int NrParam)
{
#if 0
	struct CamCtx *ctx;
	int i, ret = 0;

	if ((cam == NULL) || (CtxID < 0) || (CtxID >= CONTEXT_PER_PLATFORM))
		return -EINVAL;
	ctx = cam->ctx[CtxID];
	if (ctx == NULL)
		return -ENODEV;

	for (i = 0; i < NrParam; i++) {
		struct media_entity *me;
		switch (ParamList[i].ParamName) {
		case PARAM_SRC_SET_COMBO:
			ret = CamNodeSetCombo(ctx->src, ParamList[i].ParamArg);
			if (ret < 0)
				goto exit;
			break;
		case PARAM_SRC_GET_COMBO:
			ret = CamNodeGetCombo(ctx->src, ParamList[i].ParamArg);
			if (ret < 0)
				goto exit;
			break;
		case PARAM_CROP_SET_COMBO:
			ret = CamNodeSetCombo(ctx->crop, ParamList[i].ParamArg);
			if (ret < 0)
				goto exit;
			break;
		case PARAM_CROP_GET_COMBO:
			ret = CamNodeGetCombo(ctx->crop, ParamList[i].ParamArg);
			if (ret < 0)
				goto exit;
			break;
		case PARAM_PATH_SET_CROP:
			ret = CamNodeSetCrop(ctx->path, ParamList[i].ParamArg);
			if (ret < 0)
				goto exit;
			break;
		case PARAM_PATH_GET_CROP:
			ret = CamNodeGetCrop(ctx->path, ParamList[i].ParamArg);
			if (ret < 0)
				goto exit;
			break;
		default:
			app_err("unknown parameter name: %d", ParamList[i].ParamName);
		}
	}
	ret = CamNodeSetCtrl(ctx->path, ctx);
exit:
	return ret;
#else
	return 0;
#endif
}

int CameraContextKill(struct PlatCam *cam, int CtxID)
{
#if 0
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

	app_info("context%d [source'%s' => crop'%s' => path'%s' => %d outputs] removed", CtxID, ctx->src->name, ctx->crop->name, ctx->path->name, ctx->NrOut);
	free(ctx->out);
	free(ctx);
	cam->ctx[CtxID] = NULL;
	return ret;
#else
	return 0;
#endif
}

int CameraContextOutputOpen(struct PlatCam *cam, int CtxID, int port)
{
#if 0
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
		return errno;
	}
	SetFlag(ctx, CAMCTX_FL_DST1_BUSY + port);
	return out->me->fd;
#else
	return 0;
#endif
}

int CameraContextOutputClose(struct PlatCam *cam, int CtxID, int port)
{
#if 0
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
#else
	return 0;
#endif
}

int CameraContextInputOpen(struct PlatCam *cam, int CtxID)
{
#if 0
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
		return errno;
	}
	SetFlag(ctx, CAMCTX_FL_INPUT_BUSY);
	return in->me->fd;
#else
	return 0;
#endif
}

int CameraContextInputClose(struct PlatCam *cam, int CtxID)
{
#if 0
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
#else
	return 0;
#endif
}

int CameraContextPathGet(struct PlatCam *cam, int CtxID)
{
#if 0
	struct CamNode *path;

	if (CtxID >= CONTEXT_PER_PLATFORM)
		return -EINVAL;
	if (cam->ctx[CtxID] == NULL)
		return -ENODEV;
	path = cam->ctx[CtxID]->path;

	return path->me->fd;
#else
	return 0;
#endif
}

int CameraContextPathPut(struct PlatCam *cam, int CtxID)
{
#if 0
	if (CtxID >= CONTEXT_PER_PLATFORM)
		return -EINVAL;
	if (cam->ctx[CtxID] == NULL)
		return -ENODEV;

	return 0;
#else
	return 0;
#endif
}

int CameraContextSourceGet(struct PlatCam *cam, int CtxID)
{
#if 0
	struct CamNode *src;

	if (CtxID >= CONTEXT_PER_PLATFORM)
		return -EINVAL;
	if (cam->ctx[CtxID] == NULL)
		return -ENODEV;
	src = cam->ctx[CtxID]->src;

	if (src->me->info.type != MEDIA_ENT_T_V4L2_SUBDEV_SENSOR)
		return -EPERM;

	return CamNodeOpen(src);
#else
	return 0;
#endif
}

int CameraContextSourcePut(struct PlatCam *cam, int CtxID)
{
#if 0
	if (CtxID >= CONTEXT_PER_PLATFORM)
		return -EINVAL;
	if (cam->ctx[CtxID] == NULL)
		return -ENODEV;

	return CamNodeClose(cam->ctx[CtxID]->src);
#else
	return 0;
#endif
}
