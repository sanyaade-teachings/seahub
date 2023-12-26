"use strict";(self.webpackChunkseahub_frontend=self.webpackChunkseahub_frontend||[]).push([[539],{53854:function(e,n,r){var t=r(72791),i=r(54164),o=r(72838),a=r(50906),s=r(95996),c=r(63446),u=r(15671),d=r(43144),h=r(60136),l=r(29388),g=r(74014),p=r(98015),f=r(51832),S=r(22386),m=r(65953),D=r(80184),I=function(e){(0,h.Z)(r,e);var n=(0,l.Z)(r);function r(e){var t;return(0,u.Z)(this,r),(t=n.call(this,e)).onInternalLinkToggle=function(){t.setState({isShowInternalLinkDialog:!t.state.isShowInternalLinkDialog})},t.unmark=function(){var e=t.props,n=e.repoID,r=e.docPath;p.I.sdocUnmarkAsDraft(n,r).then((function(e){t.props.unmarkDraft()})).catch((function(e){var n=s.c.getErrorMsg(e);f.Z.danger(n)}))},t.toggleStar=function(){var e=t.props,n=e.isStarred,r=e.repoID,i=e.docPath;n?p.I.unstarItem(r,i).then((function(e){t.props.toggleStar(!1)})).catch((function(e){var n=s.c.getErrorMsg(e);f.Z.danger(n)})):p.I.starItem(r,i).then((function(e){t.props.toggleStar(!0)})).catch((function(e){var n=s.c.getErrorMsg(e);f.Z.danger(n)}))},t.onShareToggle=function(){t.setState({isShowShareDialog:!t.state.isShowShareDialog})},t.onFreezeDocument=function(){var e=t.props,n=e.repoID,r=e.docPath;p.I.lockfile(n,r,-1).then((function(e){g.Nd.getInstance().dispatch(g.dK.REFRESH_DOCUMENT)})).catch((function(e){var n=s.c.getErrorMsg(e);f.Z.danger(n)}))},t.unFreeze=function(){var e=t.props,n=e.repoID,r=e.docPath;p.I.unlockfile(n,r).then((function(e){g.Nd.getInstance().dispatch(g.dK.REFRESH_DOCUMENT)})).catch((function(e){var n=s.c.getErrorMsg(e);f.Z.danger(n)}))},t.state={isShowInternalLinkDialog:!1,isShowShareDialog:!1},t}return(0,d.Z)(r,[{key:"componentDidMount",value:function(){var e=g.Nd.getInstance();this.unsubscribeInternalLinkEvent=e.subscribe(g.dK.INTERNAL_LINK_CLICK,this.onInternalLinkToggle),this.unsubscribeStar=e.subscribe(g.dK.TOGGLE_STAR,this.toggleStar),this.unsubscribeUnmark=e.subscribe(g.dK.UNMARK_AS_DRAFT,this.unmark),this.unsubscribeShare=e.subscribe(g.dK.SHARE_SDOC,this.onShareToggle),this.unsubscribeShare=e.subscribe(g.dK.FREEZE_DOCUMENT,this.onFreezeDocument),this.unsubscribeShare=e.subscribe(g.dK.UNFREEZE,this.unFreeze)}},{key:"componentWillUnmount",value:function(){this.unsubscribeInternalLinkEvent(),this.unsubscribeStar(),this.unsubscribeUnmark(),this.unsubscribeShare()}},{key:"render",value:function(){var e=this.props,n=e.repoID,r=e.docPath,t=e.docName,i=e.docPerm,o=this.state,a=o.isShowInternalLinkDialog,s=o.isShowShareDialog;return(0,D.jsxs)(D.Fragment,{children:[a&&(0,D.jsx)(S.Z,{repoID:n,path:r,onInternalLinkDialogToggle:this.onInternalLinkToggle}),s&&(0,D.jsx)(m.Z,{itemType:"file",itemPath:r,itemName:t,repoID:n,userPerm:i,toggleDialog:this.onShareToggle})]})}}]),r}(t.Component),b=I,v=function(e){(0,h.Z)(r,e);var n=(0,l.Z)(r);function r(e){var t;(0,u.Z)(this,r),(t=n.call(this,e)).toggleStar=function(e){t.setState({isStarred:e})},t.unmarkDraft=function(){t.setState({isDraft:!1})};var i=window.app.pageOptions,o=i.isStarred,a=i.isSdocDraft;return t.state={isStarred:o,isDraft:a},t}return(0,d.Z)(r,[{key:"componentDidMount",value:function(){var e=window.seafile.docName,n=s.c.getFileIconUrl(e,192);document.getElementById("favicon").href=n}},{key:"render",value:function(){var e=window.seafile,n=e.repoID,r=e.docPath,i=e.docName,o=e.docPerm,a=this.state,s=a.isStarred,c=a.isDraft;return(0,D.jsxs)(t.Fragment,{children:[(0,D.jsx)(g.Qo,{isStarred:s,isDraft:c}),(0,D.jsx)(b,{repoID:n,docPath:r,docName:i,docPerm:o,isStarred:s,toggleStar:this.toggleStar,unmarkDraft:this.unmarkDraft})]})}}]),r}(t.Component),k=window.app.config,w=k.serviceURL,U=k.avatarURL,E=k.siteRoot,P=k.lang,F=k.mediaUrl,L=k.isPro,R=window.app.userInfo,N=R.username,Z=R.name,T=window.app.pageOptions,C=T.repoID,y=T.repoName,K=T.parentDir,M=T.filePerm,_=T.docPath,j=T.docName,x=T.docUuid,A=T.seadocAccessToken,O=T.seadocServerUrl,z=T.assetsUrl,H=T.isSdocRevision,B=T.isPublished,G=T.originFilename,V=T.revisionCreatedAt,Q=T.originFileVersion,W=T.originFilePath,q=T.originDocUuid,J=T.revisionId,X=T.isFreezed;window.seafile={repoID:C,docPath:_,docName:j,docUuid:x,isOpenSocket:!0,serviceUrl:w,accessToken:A,sdocServer:O,name:Z,username:N,avatarURL:U,siteRoot:E,docPerm:M,historyURL:s.c.generateHistoryURL(E,C,_),parentFolderURL:"".concat(E,"library/").concat(C,"/").concat(s.c.encodePath(y+K)),assetsUrl:z,isShowInternalLink:!0,isStarIconShown:!0,isSdocRevision:H,isPublished:B,originFilename:G,originFileVersion:Q,originFilePath:W,originDocUuid:q,revisionCreatedAt:V,lang:P,revisionId:J,mediaUrl:F,isFreezed:X,isPro:"True"===L},i.render((0,D.jsx)(o.a3,{i18n:a.Z,children:(0,D.jsx)(t.Suspense,{fallback:(0,D.jsx)(c.Z,{}),children:(0,D.jsx)(v,{})})}),document.getElementById("wrapper"))}},function(e){e.O(0,[351],(function(){return n=53854,e(e.s=n);var n}));e.O()}]);
//# sourceMappingURL=viewFileSdoc.5c117b4c.js.map