"use strict";(self.webpackChunkseahub_frontend=self.webpackChunkseahub_frontend||[]).push([[824],{30276:function(e,n,i){i.d(n,{Z:function(){return l}});var t=i(15671),o=i(43144),s=i(60136),r=i(29388),a=i(72791),c=i(80184),d=function(e){(0,s.Z)(i,e);var n=(0,r.Z)(i);function i(){var e;(0,t.Z)(this,i);for(var o=arguments.length,s=new Array(o),r=0;r<o;r++)s[r]=arguments[r];return(e=n.call.apply(n,[this].concat(s))).onBackClick=function(e){e.preventDefault(),window.history.back()},e}return(0,o.Z)(i,[{key:"render",value:function(){return(0,c.jsx)("div",{className:"go-back",onClick:this.onBackClick,children:(0,c.jsx)("span",{className:"fas fa-chevron-left"})})}}]),i}(a.Component),l=d},51638:function(e,n,i){var t=i(15671),o=i(43144),s=i(60136),r=i(29388),a=i(72791),c=i(54164),d=i(81694),l=i.n(d),h=i(81815),u=i(79501),f=i(53585),v=i(63446),g=i(30276),m=i(95996),p=i(22228),x=(i(28421),i(51832)),w=i(80184),j=window.app.config,k=j.serviceURL,C=j.avatarURL,Z=j.siteRoot,N=window.app.pageOptions,b=N.username,L=N.name,y=window.sdocRevision,M=y.repoID,R=y.fileName,P=y.filePath,U=y.docUuid,E=y.assetsUrl,D=y.fileDownloadLink,I=y.originFileDownloadLink;window.seafile={repoID:M,docPath:P,docName:R,docUuid:U,isOpenSocket:!1,serviceUrl:k,name:L,username:b,avatarURL:C,siteRoot:Z,assetsUrl:E};var O=function(e){(0,s.Z)(i,e);var n=(0,r.Z)(i);function i(e){var o;return(0,t.Z)(this,i),(o=n.call(this,e)).edit=function(e){e.stopPropagation(),e.nativeEvent.stopImmediatePropagation(),window.location.href="".concat(Z,"lib/").concat(M,"/file").concat(P)},o.publishRevision=function(e){e.stopPropagation(),e.nativeEvent.stopImmediatePropagation(),p.I.sdocPublishRevision(U).then((function(e){var n=e.data.origin_file_path;window.location.href="".concat(Z,"lib/").concat(M,"/file").concat(n)})).catch((function(e){var n=m.c.getErrorMsg(e,!1);x.Z.danger((0,f.ih)(n))}))},o.renderContent=function(){var e=o.state,n=e.isLoading,i=e.errorMessage,t=e.revisionContent,s=e.originContent;return n?(0,w.jsx)("div",{className:"sdoc-revision-viewer h-100 d-flex align-items-center justify-content-center",children:(0,w.jsx)(v.Z,{})}):i?(0,w.jsx)("div",{className:"sdoc-revision-viewer h-100 d-flex align-items-center justify-content-center",children:(0,f.ih)(i)}):(0,w.jsx)(u.ZX,{currentContent:t,lastContent:s})},o.state={isLoading:!0,errorMessage:"",revisionContent:"",originContent:""},o}return(0,o.Z)(i,[{key:"componentDidMount",value:function(){var e=this;fetch(D).then((function(e){return e.json()})).then((function(n){fetch(I).then((function(e){return e.json()})).then((function(i){e.setState({revisionContent:n,originContent:i,isLoading:!1,errorMessage:""})})).catch((function(n){var i=m.c.getErrorMsg(n,!0);e.setState({isLoading:!1,errorMessage:i})}))})).catch((function(n){var i=m.c.getErrorMsg(n,!0);e.setState({isLoading:!1,errorMessage:i})}))}},{key:"render",value:function(){var e=this.state,n=e.isLoading,i=e.errorMessage;return(0,w.jsx)("div",{className:"sdoc-revision d-flex h-100 w-100 o-hidden",children:(0,w.jsxs)("div",{className:"sdoc-revision-container d-flex flex-column",children:[(0,w.jsxs)("div",{className:"sdoc-revision-header pl-4 pr-4 d-flex justify-content-between w-100 o-hidden",children:[(0,w.jsxs)("div",{className:l()("sdoc-revision-header-left h-100 d-flex align-items-center o-hidden"),children:[(0,w.jsx)(g.Z,{}),(0,w.jsx)("div",{className:"file-name text-truncate",children:R})]}),(0,w.jsx)("div",{className:"sdoc-revision-header-right h-100 d-flex align-items-center",children:!n&&!i&&(0,w.jsxs)(w.Fragment,{children:[(0,w.jsx)(h.Z,{color:"success",className:"mr-4",onClick:this.edit,children:(0,f.ih)("Edit")}),(0,w.jsx)(h.Z,{color:"success",onClick:this.publishRevision,children:(0,f.ih)("Publish")})]})})]}),(0,w.jsx)("div",{className:"sdoc-revision-content f-flex",children:this.renderContent()})]})})}}]),i}(a.Component);c.render((0,w.jsx)(O,{}),document.getElementById("wrapper"))}},function(e){e.O(0,[351],(function(){return n=51638,e(e.s=n);var n}));e.O()}]);
//# sourceMappingURL=sdocRevision.b90bd4f0.js.map