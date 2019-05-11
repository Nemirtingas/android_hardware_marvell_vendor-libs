#ifndef MEDIALIB_H
#define MEDIALIB_H

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef ANDROID
#include <android/log.h>
#endif

#include "mediactl.h"
#include "v4l2subdev.h"

#define ME_CNT	50

__BEGIN_DECLS

struct isp_subdev {
	struct media_entity	*me;
	int			fd;
	struct isp_subdev_ops	*ops;
};

struct isp_subdev_ops {
	int (*open)(struct isp_subdev *isd);
	void (*close)(struct isp_subdev *isd);
	int (*enum_path)(struct isp_subdev *isd);
};

struct CamLink {
	struct CamNode		*src;
	struct CamNode		*dst;
	struct media_link	*mlink;
	int			RefCnt;
};

struct CamRoute {
	struct CamNode	*src;
	struct CamNode	*dst;
	struct CamLink	*head;
	struct CamRoute	*more;
	int		RefCnt;
};

enum {
	/* TYPE flags */
	CAMNODE_FL_T_SOURCE = 0,
	CAMNODE_FL_T_INPUT,
	CAMNODE_FL_T_PRECROP,
	CAMNODE_FL_T_PATH,
	CAMNODE_FL_T_POSTCROP,
	CAMNODE_FL_T_OUTPUT,
	/* STATE flags */
	CAMNODE_FL_S_OCCUPY,
};

enum {
	CAMCTX_FL_INPUT_BUSY = 0,
	CAMCTX_FL_DST1_BUSY,
	CAMCTX_FL_DST2_BUSY,
	CAMCTX_FL_DST3_BUSY,
	CAMCTX_FL_DST4_BUSY,
	CAMCTX_FL_DST5_BUSY,
	CAMCTX_FL_DST6_BUSY,
	CAMCTX_FL_INIT,
};

#define SetFlag(n, f)	((n)->flags |= (1 << (f)))
#define ClrFlag(n, f)	((n)->flags &= ~(1 << (f)))
#define TstFlag(n, f)	((n)->flags & (1 << (f)))

struct CamNode {
	struct media_entity	*me;
	int			OpenCnt;
	int			id;
	char			name[32];
	int			flags;
	void			*param;
	void			*host;
	struct PlatCam		*plat;

	struct CamNodeOps	*ops;

	struct CamLink		**link;	/* direct link */
	int			NrLink;
	struct CamRoute		**route; /* Reachable dests */
	int			NrRoute;
	__u32			level;
};

struct CamNodeOps {
	int (*open)(struct CamNode *node);
	void (*close)(struct CamNode *node);
	int (*EnumPath)(struct CamNode *node);
	int (*EnumLink)(struct CamNode *node, int index, void *ilink);
	int (*SetLink)(struct CamNode *node, void *ilink, int flags);
};

struct CamCtx {
	struct CamRoute	*route;
	struct CamNode	*src;
	struct CamNode	*crop;
	struct CamNode	*path;
	struct CamRoute **out;
	int		NrOut;
	long		flags;
};

#define SetContainer(g, h)	((g)->padding[0] = (__u32)h)
#define GetContainer(g)		((void *)((g)->padding[0]))

/**************************** External Data Types ****************************/
#define CONTEXT_PER_PLATFORM	10

struct PlatCam {
	struct media_device	*media;
	struct CamNode		*node[ME_CNT];
	int			NrME;
	struct CamNode		*SrcPool[ME_CNT];
	int			NrSrc;
	struct CamNode		*PathPool[ME_CNT];
	int			NrPath;
	struct CamNode		*DstPool[ME_CNT];
	int			NrDst;
	struct CamCtx		*ctx[CONTEXT_PER_PLATFORM];
	int			NrCtx;
	struct CamLink		*(*FindLink)(struct PlatCam *cam, struct CamNode *src, struct CamNode *dst);
};


struct FrmSzEnum {
	__u32	index;
	__u32	WMin;
	__u32	WMax;
	__u32	HMin;
	__u32	HMax;
	struct v4l2_fract fps;
};

struct FmtEnum {
	__u32	index;
	__u32	code;
	__u32	NrFrmSz;
	struct FrmSzEnum **FrmSz;
};

struct CamNodeFmtEnum {
	__u32	index;
	__u32	NrFmt;
	struct FmtEnum	**Fmt;
};

struct CamNodeEnum {
	int	index;
	char	name[32];
	int	NrRoute;
	struct CamRoute		*const*route;
	struct CamNodeFmtEnum	*FmtEnum;
};

struct PlatCam *MediaLibInit();
void MediaLibExit(struct PlatCam *);
int MediaLibEnumSource(struct PlatCam *cam, int idx, struct CamNodeEnum *desc);
int MediaLibEnumPath(struct PlatCam *cam, int idx, struct CamNodeEnum *desc);

enum {
	PARAM_SRC_SET_COMBO = 0,
	PARAM_SRC_GET_COMBO,
	PARAM_CROP_SET_COMBO,
	PARAM_CROP_GET_COMBO,
	PARAM_PATH_SET_CROP,
	PARAM_PATH_GET_CROP,	/* Beware! Change to above parameters may impact all linked down stream components */
	PARAM_PATH_CMD_FLUSH,
	PARAM_CNT,
	PARAM_APPLY_FMT = 0,
	PARAM_APPLY_CROP,
};

struct CamCtxParam {
	unsigned int	ParamName;
	void		*ParamArg;
};

struct CamNodeFmtCombo {
	__u32	which;
	__u32	pad;
	struct v4l2_rect	CropWnd;
	__u32	width;
	__u32	height;
	__u32	code;
	__u8	scope;	/* If bit[PARAM_APPLY_FMT] set: apply w/h/c. if bit[PARAM_APPLY_CROP] set: apply CropWnd */
};

/*
 * Initialize a context with specified source and path id and outputs
 * @cam:	media-lib handle
 * @SrcID:	Source ID, as enumerated by MediaLibEnumSource
 * @PathID:	Source ID, as enumerated by MediaLibEnumPath
 * @NrDst:	Number of output streams attached to this path
 * return:	<0: Media-lib error number
 *		>=0: context ID
 */
int CameraContextInit(struct PlatCam *cam, int SrcID, int PathID, int NrDst);

/*
 * Configure context component parameters, mainly realted to path configuration
 * @cam:	media-lib handle
 * @CtxID:	context ID
 * @ParamList:	a pair of <ops, arg> as defined by struct CamCtxParam
 * @NrParam:	Number of parameters to be applied
 * return:	<0: Media-lib error number
 *		>=0: success
 */
int CameraContextPara(struct PlatCam *cam, int CtxID, struct CamCtxParam *ParamList, int NrParam);

/*
 * Destroy a context with specified context id
 * @cam:	media-lib handle
 * @CtxID:	context ID
 * return:	<0: Media-lib error number
 *		>=0: success
 */
int CameraContextKill(struct PlatCam *cam, int CtxID);

/*
 * Open video device node of context output, and get fd
 * @cam:	media-lib handle
 * @CtxID:	context ID
 * @port:	output port number per context, should be smaller than CameraContextInit@NrDst
 * return:	<0: kernel error number
 *		>=0: fd number as returned by open("/dev/videoX", O_RDWR | O_NONBLOCK)
 */
int CameraContextOutputOpen(struct PlatCam *cam, int CtxID, int port);

/*
 * Release fd, and close video device node of context output
 * @cam:	media-lib handle
 * @CtxID:	context ID
 * @port:	output port number per context, should be smaller than CameraContextInit@NrDst
 * return:	<0: media-lib error number
 *		>=0: success
 */

int CameraContextOutputClose(struct PlatCam *cam, int CtxID, int port);

/*
 * Open video device node of context input, and get fd
 * @cam:	media-lib handle
 * @CtxID:	context ID
 * return:	<0: kernel error number
 *		>=0: fd number as returned by open("/dev/videoX", O_RDWR | O_NONBLOCK)
 */
int CameraContextInputOpen(struct PlatCam *cam, int CtxID);

/*
 * Release fd, and close video device node of context input
 * @cam:	media-lib handle
 * @CtxID:	context ID
 * return:	<0: media-lib error number
 *		>=0: success
 */
int CameraContextInputClose(struct PlatCam *cam, int CtxID);

/*
 * Get subdev fd of context path
 * @cam:	media-lib handle
 * @CtxID:	context ID
 * return:	<0: kernel error number
 *		>=0: fd number as returned by open("/dev/v4l-subdevX", O_RDWR | O_NONBLOCK)
 */
int CameraContextPathGet(struct PlatCam *cam, int CtxID);

/*
 * Release subdev fd of context path
 * @cam:	media-lib handle
 * @CtxID:	context ID
 * return:	<0: media-lib error number
 *		>=0: success
 */
int CameraContextPathPut(struct PlatCam *cam, int CtxID);

/*
 * Get subdev fd of context source
 * @cam:	media-lib handle
 * @CtxID:	context ID
 * return:	<0: kernel error number
 *		>=0: fd number as returned by open("/dev/v4l-subdevX", O_RDWR | O_NONBLOCK)
 */
int CameraContextSourceGet(struct PlatCam *cam, int CtxID);

/*
 * Release subdev fd of context source
 * @cam:	media-lib handle
 * @CtxID:	context ID
 * return:	<0: media-lib error number
 *		>=0: success
 */
int CameraContextSourcePut(struct PlatCam *cam, int CtxID);

void OpenCam(struct PlatCam *cam, int srcID);
void CloseCam(struct PlatCam *cam, int srcID);

struct CtxNodeConfig {
	struct CamNode			*node;
	struct v4l2_mbus_framefmt	OutFmt;
};

__END_DECLS

#define V4L2_CID_PRIVATE_GET_ROLE \
					(V4L2_CID_CAMERA_CLASS_BASE + 0x1002)

#ifdef ANDROID
#define app_err(format, arg...)		\
	do { \
	__android_log_print(ANDROID_LOG_ERROR, "MediaLib", format "\n", ## arg); \
	} while (0)
#define app_warn(format, arg...)		\
	do { \
	__android_log_print(ANDROID_LOG_WARN, "MediaLib", format "\n", ## arg); \
	} while (0)
#define app_info(format, arg...)		\
	do { \
	__android_log_print(ANDROID_LOG_INFO, "MediaLib", format "\n", ## arg); \
	} while (0)
#else
#define app_err(format, arg...)		\
	do { \
	printf("[app:ERROR]: " format "\n", ## arg); \
	fflush(stdout); \
	} while (0)
#define app_warn(format, arg...)		\
	do { \
	printf("[app:WARNING]: " format "\n", ## arg); \
	fflush(stdout); \
	} while (0)
#define app_info(format, arg...)		\
	do { \
	printf("[app:INFO]: " format "\n", ## arg); \
	fflush(stdout); \
	} while (0)
#endif

#endif
