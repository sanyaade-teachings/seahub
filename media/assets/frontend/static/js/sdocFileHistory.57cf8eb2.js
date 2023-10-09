"use strict";(self.webpackChunkseahub_frontend=self.webpackChunkseahub_frontend||[]).push([[514],{30276:function(e,n,t){t.d(n,{Z:function(){return h}});var s=t(15671),i=t(43144),o=t(60136),r=t(29388),a=t(72791),c=t(80184),l=function(e){(0,o.Z)(t,e);var n=(0,r.Z)(t);function t(){var e;(0,s.Z)(this,t);for(var i=arguments.length,o=new Array(i),r=0;r<i;r++)o[r]=arguments[r];return(e=n.call.apply(n,[this].concat(o))).onBackClick=function(e){e.preventDefault(),window.history.back()},e}return(0,i.Z)(t,[{key:"render",value:function(){return(0,c.jsx)("div",{className:"go-back",onClick:this.onBackClick,children:(0,c.jsx)("span",{className:"fas fa-chevron-left"})})}}]),t}(a.Component),h=l},67145:function(e,n,t){var s=t(15671),i=t(43144),o=t(60136),r=t(29388),a=t(72791),c=t(53585),l=t(95996),h=t(51832),d=t(80184),u=function(e){(0,o.Z)(t,e);var n=(0,r.Z)(t);function t(e){var i;return(0,s.Z)(this,t),(i=n.call(this,e)).onClick=function(e){i.inputRef.current.contains(e.target)||i.onRenameConfirm()},i.onChange=function(e){i.setState({name:e.target.value})},i.onKeyDown=function(e){e.keyCode===l.c.keyCodes.enter?i.onRenameConfirm(e):e.keyCode===l.c.keyCodes.esc&&i.onRenameCancel(e),e.nativeEvent.stopImmediatePropagation()},i.onRenameConfirm=function(e){e&&e.nativeEvent.stopImmediatePropagation();var n=i.state.name.trim();if(n!==i.props.name){var t=i.validateInput(),s=t.isValid,o=t.errMessage;s?i.props.onRenameConfirm(n):(h.Z.danger(o),i.props.onRenameCancel())}else i.props.onRenameCancel()},i.onRenameCancel=function(e){e.nativeEvent.stopImmediatePropagation(),i.props.onRenameCancel()},i.validateInput=function(){var e=i.state.name.trim(),n=!0,t="";return e?e.indexOf("/")>-1?{isValid:n=!1,errMessage:t=(0,c.ih)("Name should not include '/'.")}:{isValid:n,errMessage:t}:{isValid:n=!1,errMessage:t=(0,c.ih)("Name is required.")}},i.state={name:e.name},i.inputRef=a.createRef(),i}return(0,i.Z)(t,[{key:"componentDidMount",value:function(){var e=this;if(this.inputRef.current.focus(),this.props.hasSuffix){var n=this.props.name.lastIndexOf(".");this.inputRef.current.setSelectionRange(0,n,"forward")}else this.inputRef.current.setSelectionRange(0,-1);setTimeout((function(){document.addEventListener("click",e.onClick)}),1)}},{key:"componentWillUnmount",value:function(){document.removeEventListener("click",this.onClick)}},{key:"render",value:function(){return(0,d.jsx)("div",{className:"rename-container",children:(0,d.jsx)("input",{ref:this.inputRef,value:this.state.name,onChange:this.onChange,onKeyDown:this.onKeyDown})})}}]),t}(a.Component);n.Z=u},60377:function(e,n,t){var s=t(15671),i=t(43144),o=t(60136),r=t(29388),a=t(72791),c=t(54164),l=t(98290),h=t(81694),d=t.n(h),u=t(79501),f=t(22228),m=t(53585),g=t(63446),p=t(30276),v=t(93433),y=t(95996),x=t(39571),C=t(51832),S=t(72426),w=t.n(S),j=t(61599),V=t(20387),R=t(59508),Z=t(52919),N=t(69498),k=t(67145),I=(t(45020),t(80184));w().locale(window.app.config.lang);var M=function(e){(0,o.Z)(t,e);var n=(0,r.Z)(t);function t(e){var i;return(0,s.Z)(this,t),(i=n.call(this,e)).onMouseEnter=function(){var e=i.props,n=e.currentVersion,t=e.historyVersion;n.commit_id!==t.commit_id&&i.setState({isShowOperationIcon:!0})},i.onMouseLeave=function(){var e=i.props,n=e.currentVersion,t=e.historyVersion;n.commit_id!==t.commit_id&&i.setState({isShowOperationIcon:!1})},i.onToggleClick=function(e){i.setState({isMenuShow:!i.state.isMenuShow})},i.onClick=function(){i.setState({isShowOperationIcon:!1});var e=i.props,n=e.currentVersion,t=e.historyVersion;n.commit_id!==t.commit_id&&i.props.onSelectHistoryVersion(t)},i.onRestore=function(){var e=i.props.historyVersion;i.props.onRestore(e)},i.onItemDownload=function(){},i.onItemCopy=function(){var e=i.props.historyVersion;e.ctime_format=w()(e.ctime).format("YYYY-MM-DD HH:mm"),i.props.onCopy(e)},i.toggleRename=function(){i.setState({isRenameShow:!i.state.isRenameShow})},i.onRenameConfirm=function(e){var n=i.props.historyVersion.obj_id;i.props.renameHistoryVersion(n,e),i.toggleRename()},i.onRenameCancel=function(){i.toggleRename()},i.state={isShowOperationIcon:!1,isMenuShow:!1,isRenameShow:!1},i}return(0,i.Z)(t,[{key:"render",value:function(){var e=this.props,n=e.currentVersion,t=e.historyVersion;if(!n||!t)return null;var s=t.ctime,i=t.commit_id,o=t.creator_name,r=t.obj_id,a=t.name,c=i===n.commit_id,l=N.Z.getUrl({type:"download_historic_file",filePath:m.bc,objID:r});return(0,I.jsxs)("li",{className:"history-list-item ".concat(c?"item-active":""),onMouseEnter:this.onMouseEnter,onMouseLeave:this.onMouseLeave,onClick:this.onClick,children:[(0,I.jsxs)("div",{className:"history-info",children:[this.state.isRenameShow?(0,I.jsx)(k.Z,{name:a,onRenameConfirm:this.onRenameConfirm,onRenameCancel:this.onRenameCancel}):(0,I.jsx)("div",{className:"name",children:a}),(0,I.jsx)("div",{className:"time",children:w()(s).format("YYYY-MM-DD HH:mm")}),(0,I.jsxs)("div",{className:"owner",children:[(0,I.jsx)("span",{className:"squire-icon"}),(0,I.jsx)("span",{children:o})]})]}),(0,I.jsx)("div",{className:"history-operation",children:(0,I.jsxs)(j.Z,{isOpen:this.state.isMenuShow,toggle:this.onToggleClick,children:[(0,I.jsx)(V.Z,{tag:"a",className:"fas fa-ellipsis-v ".concat(this.state.isShowOperationIcon||c?"":"invisible"),"data-toggle":"dropdown","aria-expanded":this.state.isMenuShow,alt:(0,m.ih)("More Operations")}),(0,I.jsxs)(R.Z,{children:[(0,I.jsx)(Z.Z,{tag:"a",href:l,onClick:this.onItemDownLoad,children:(0,m.ih)("Download")}),0!==this.props.index&&(0,I.jsx)(Z.Z,{onClick:this.onItemCopy,children:(0,m.ih)("Copy")}),(0,I.jsx)(Z.Z,{onClick:this.toggleRename,children:(0,m.ih)("Rename")})]})]})})]})}}]),t}(a.Component);var H=function(e){var n=e.onChange,t=e.checked,s=e.placeholder,i=e.disabled,o=e.className,r=e.size;return(0,I.jsx)("div",{className:d()("seahub-switch position-relative",o,r),children:(0,I.jsxs)("label",{className:"custom-switch",children:[(0,I.jsx)("input",{className:"custom-switch-input",type:"checkbox",checked:t,onChange:n,name:"custom-switch-checkbox",disabled:i}),(0,I.jsx)("span",{className:"custom-switch-description text-truncate",children:s}),(0,I.jsx)("span",{className:"custom-switch-indicator"})]})})},_=window.fileHistory.pageOptions.docUuid,D=function(e){(0,o.Z)(t,e);var n=(0,r.Z)(t);function t(e){var i;return(0,s.Z)(this,t),(i=n.call(this,e)).loadMore=function(){if(!i.state.isReloadingData){var e=i.state.currentPage+1;i.setState({currentPage:e,isReloadingData:!0}),f.I.listSdocHistory(_,e,m.LZ).then((function(e){i.updateResultState(e.data),i.setState({isReloadingData:!1})}))}},i.renameHistoryVersion=function(e,n){f.I.renameSdocHistory(_,e,n).then((function(t){i.setState({historyVersions:i.state.historyVersions.map((function(t){return t.obj_id==e&&(t.name=n),t}))})})).catch((function(e){var n=y.c.getErrorMsg(e,!0);i.setState({isLoading:!1,errorMessage:n})}))},i.onScrollHandler=function(e){var n=e.target.clientHeight,t=e.target.scrollHeight;n+e.target.scrollTop+1>=t&&i.state.hasMore&&i.loadMore()},i.restoreVersion=function(e){var n=e.commit_id,t=e.path;x.Z.revertFile(t,n).then((function(e){e.data.success&&(i.setState({isLoading:!0}),i.refershFileList());var n=(0,m.ih)("Successfully restored.");C.Z.success(n)})).catch((function(e){var n=y.c.getErrorMsg(e,!0);C.Z.danger((0,m.ih)(n))}))},i.onSelectHistoryVersion=function(e){if(i.props.isShowChanges){var n=i.state.historyVersions,t=n.findIndex((function(n){return n.commit_id===e.commit_id}));i.props.onSelectHistoryVersion(e,n[t+1])}else i.props.onSelectHistoryVersion(e)},i.copyHistoryFile=function(e){var n=e.path,t=e.obj_id,s=e.ctime_format;f.I.sdocCopyHistoryFile(m.y8,n,t,s).then((function(e){var n=(0,m.ih)("Successfully copied %(name)s."),t=e.data.file_name;n=n.replace("%(name)s",t),C.Z.success(n)})).catch((function(e){var n=y.c.getErrorMsg(e,!0);C.Z.danger((0,m.ih)(n))}))},i.renderHistoryVersions=function(){var e=i.state,n=e.isLoading,t=e.historyVersions,s=e.errorMessage;return 0===t.length?n?(0,I.jsx)("div",{className:"h-100 w-100 d-flex align-items-center justify-content-center",children:(0,I.jsx)(g.Z,{})}):s?(0,I.jsx)("div",{className:"h-100 w-100 d-flex align-items-center justify-content-center error-message",children:(0,m.ih)(s)}):(0,I.jsx)("div",{className:"h-100 w-100 d-flex align-items-center justify-content-center empty-tip-color",children:(0,m.ih)("No version history")}):(0,I.jsxs)(I.Fragment,{children:[t.map((function(e,n){return(0,I.jsx)(M,{index:n,currentVersion:i.props.currentVersion,historyVersion:e,onSelectHistoryVersion:i.onSelectHistoryVersion,onRestore:i.restoreVersion,onCopy:i.copyHistoryFile,renameHistoryVersion:i.renameHistoryVersion},e.commit_id)})),n&&(0,I.jsx)("div",{className:"loading-more d-flex align-items-center justify-content-center w-100",children:(0,I.jsx)(g.Z,{})})]})},i.onShowChanges=function(){var e=i.props,n=e.isShowChanges,t=e.currentVersion,s=i.state.historyVersions,o=s.findIndex((function(e){return e.commit_id===t.commit_id})),r=s[o+1];i.props.onShowChanges(!n,r)},i.state={isLoading:!0,historyVersions:[],errorMessage:"",currentPage:1,hasMore:!1,fileOwner:"",isReloadingData:!1},i}return(0,i.Z)(t,[{key:"componentDidMount",value:function(){var e=this;f.I.listSdocHistory(_,1,m.LZ).then((function(n){if(0===n.data.length)throw e.setState({isLoading:!1}),Error("there has an error in server");e.initResultState(n.data)}))}},{key:"refershFileList",value:function(){var e=this;f.I.listSdocHistory(_,1,m.LZ).then((function(n){e.initResultState(n.data)}))}},{key:"initResultState",value:function(e){e.histories.length&&(this.setState({historyVersions:e.histories,currentPage:e.page,hasMore:e.total_count>m.LZ*this.state.currentPage,isLoading:!1,fileOwner:e.histories[0].creator_email}),this.props.onSelectHistoryVersion(e.histories[0],e.histories[1]))}},{key:"updateResultState",value:function(e){e.histories.length&&this.setState({historyVersions:[].concat((0,v.Z)(this.state.historyVersions),(0,v.Z)(e.histories)),currentPage:e.page,hasMore:e.total_count>m.LZ*this.state.currentPage,isLoading:!1,fileOwner:e.histories[0].creator_email})}},{key:"render",value:function(){var e=this.state.historyVersions;return(0,I.jsxs)("div",{className:"sdoc-file-history-panel h-100 o-hidden d-flex flex-column",children:[(0,I.jsx)("div",{className:"sdoc-file-history-select-range",children:(0,I.jsx)("div",{className:"sdoc-file-history-select-range-title",children:(0,m.ih)("History Versions")})}),(0,I.jsx)("div",{className:d()("sdoc-file-history-versions",{"o-hidden":0===e.length}),onScroll:this.onScrollHandler,children:this.renderHistoryVersions()}),(0,I.jsx)("div",{className:"sdoc-file-history-diff-switch d-flex align-items-center",children:(0,I.jsx)(H,{checked:this.props.isShowChanges,placeholder:(0,m.ih)("Show changes"),className:"sdoc-history-show-changes w-100",size:"small",onChange:this.onShowChanges})})]})}}]),t}(a.Component),L=(t(28421),window.app.config),b=L.serviceURL,E=L.avatarURL,O=L.siteRoot,F=window.app.pageOptions,P=F.username,T=F.name,U=window.fileHistory.pageOptions,Y=U.repoID,q=U.fileName,B=U.filePath,K=U.docUuid,z=U.assetsUrl;window.seafile={repoID:Y,docPath:B,docName:q,docUuid:K,isOpenSocket:!1,serviceUrl:b,name:T,username:P,avatarURL:E,siteRoot:O,assetsUrl:z};var A=function(e){(0,o.Z)(t,e);var n=(0,r.Z)(t);function t(e){var i;(0,s.Z)(this,t),(i=n.call(this,e)).onSelectHistoryVersion=function(e,n){i.setState({isLoading:!0,currentVersion:e}),f.I.getFileRevision(m.y8,e.commit_id,e.path).then((function(e){return f.I.getFileContent(e.data)})).then((function(e){var t=e.data;n?f.I.getFileRevision(m.y8,n.commit_id,n.path).then((function(e){return f.I.getFileContent(e.data)})).then((function(e){var n=e.data;i.setContent(t,n)})).catch((function(e){var n=y.c.getErrorMsg(e,!0);C.Z.danger((0,m.ih)(n)),i.setContent(t,"")})):i.setContent(t,"")})).catch((function(e){var n=y.c.getErrorMsg(e,!0);C.Z.danger((0,m.ih)(n)),i.setContent("","")}))},i.setContent=function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:"",n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"";i.setState({currentVersionContent:e,lastVersionContent:n,isLoading:!1,changes:[],currentDiffIndex:0})},i.onShowChanges=function(e,n){if(e&&n){var t=i.state.currentVersionContent;i.setState({isLoading:!0},(function(){localStorage.setItem("seahub-sdoc-history-show-changes",e+""),f.I.getFileRevision(m.y8,n.commit_id,n.path).then((function(e){return f.I.getFileContent(e.data)})).then((function(n){var s=n.data;i.setContent(t,s),i.setState({isShowChanges:e})})).catch((function(n){var s=y.c.getErrorMsg(n,!0);C.Z.danger((0,m.ih)(s)),i.setContent(t,""),i.setState({isShowChanges:e})}))}))}else i.setState({isShowChanges:e},(function(){localStorage.setItem("seahub-sdoc-history-show-changes",e+"")}))},i.setDiffCount=function(){var e=(arguments.length>0&&void 0!==arguments[0]?arguments[0]:{value:[],changes:[]}).changes;i.setState({changes:e,currentDiffIndex:0})},i.jumpToElement=function(e){i.setState({currentDiffIndex:e},(function(){var e=i.state,n=e.currentDiffIndex,t=e.changes[n],s=document.querySelectorAll("[data-id=".concat(t,"]"))[0];s&&(i.historyContentRef.scrollTop=s.offsetTop-10)}))},i.lastChange=function(){var e=i.state,n=e.currentDiffIndex,t=e.changes;0!==n?i.jumpToElement(n-1):i.jumpToElement(t.length-1)},i.nextChange=function(){var e=i.state,n=e.currentDiffIndex;n!==e.changes.length-1?i.jumpToElement(n+1):i.jumpToElement(0)},i.renderChangesTip=function(){var e=i.state,n=e.isShowChanges,t=e.changes,s=e.currentDiffIndex;if(e.isLoading)return null;if(!n)return null;var o=t?t.length:0;return 0===o?(0,I.jsx)("div",{className:"sdoc-file-history-header-right d-flex align-items-center",children:(0,I.jsx)("div",{className:"sdoc-file-changes-container d-flex align-items-center pl-2 pr-2",children:(0,m.ih)("No changes")})}):(0,I.jsx)("div",{className:"sdoc-file-history-header-right d-flex align-items-center",children:(0,I.jsxs)("div",{className:"sdoc-file-changes-container d-flex align-items-center",children:[(0,I.jsx)("div",{className:"sdoc-file-changes-tip d-flex align-items-center justify-content-center pl-2 pr-2",children:"".concat((0,m.ih)("Changes")," ").concat(s+1,"/").concat(o)}),(0,I.jsx)("div",{className:"sdoc-file-changes-divider"}),(0,I.jsx)("div",{className:"sdoc-file-changes-last d-flex align-items-center justify-content-center",id:"sdoc-file-changes-last",onClick:i.lastChange,children:(0,I.jsx)("span",{className:"fas fa-chevron-up"})}),(0,I.jsx)("div",{className:"sdoc-file-changes-divider"}),(0,I.jsx)("div",{className:"sdoc-file-changes-next d-flex align-items-center justify-content-center",id:"sdoc-file-changes-next",onClick:i.nextChange,children:(0,I.jsx)("span",{className:"fas fa-chevron-down"})}),(0,I.jsx)(l.Z,{placement:"bottom",target:"sdoc-file-changes-last",children:(0,m.ih)("Last modification")}),(0,I.jsx)(l.Z,{placement:"bottom",target:"sdoc-file-changes-next",children:(0,m.ih)("Next modification")})]})})};var o="false"!==localStorage.getItem("seahub-sdoc-history-show-changes");return i.state={isLoading:!0,isShowChanges:o,currentVersion:{},currentVersionContent:"",lastVersionContent:"",changes:[],currentDiffIndex:0},i}return(0,i.Z)(t,[{key:"render",value:function(){var e=this,n=this.state,t=n.currentVersion,s=n.isShowChanges,i=n.currentVersionContent,o=n.lastVersionContent,r=n.isLoading;return(0,I.jsxs)("div",{className:"sdoc-file-history d-flex h-100 w-100 o-hidden",children:[(0,I.jsxs)("div",{className:"sdoc-file-history-container d-flex flex-column",children:[(0,I.jsxs)("div",{className:"sdoc-file-history-header pt-2 pb-2 pl-4 pr-4 d-flex justify-content-between w-100 o-hidden",children:[(0,I.jsxs)("div",{className:d()("sdoc-file-history-header-left d-flex align-items-center o-hidden",{"pr-4":s}),children:[(0,I.jsx)(p.Z,{}),(0,I.jsx)("div",{className:"file-name text-truncate",children:q})]}),this.renderChangesTip()]}),(0,I.jsx)("div",{className:"sdoc-file-history-content f-flex flex-column",ref:function(n){return e.historyContentRef=n},children:r?(0,I.jsx)("div",{className:"sdoc-file-history-viewer d-flex align-items-center justify-content-center",children:(0,I.jsx)(g.Z,{})}):(0,I.jsx)(u.ZX,{currentContent:i,lastContent:s?o:"",didMountCallback:this.setDiffCount})})]}),(0,I.jsx)(D,{isShowChanges:s,currentVersion:t,onSelectHistoryVersion:this.onSelectHistoryVersion,onShowChanges:this.onShowChanges})]})}}]),t}(a.Component);c.render((0,I.jsx)(A,{}),document.getElementById("wrapper"))},45020:function(){}},function(e){e.O(0,[351],(function(){return n=60377,e(e.s=n);var n}));e.O()}]);
//# sourceMappingURL=sdocFileHistory.57cf8eb2.js.map