"use strict";(self.webpackChunkseahub_frontend=self.webpackChunkseahub_frontend||[]).push([[107],{47862:function(e,t,n){var r=n(15671),s=n(43144),i=n(97326),a=n(60136),o=n(29388),c=n(47313),l=n(1168),h=n(3885),d=n(83854),u=n(61805),m=n(4514),p=n(51282),f=n(68164),x=n(68396),j=n(24213),g=n(42995),v=n(12756),b=n(12213),N=n(7764),k=n(21303),w=n(46417),Z=function(e){(0,a.Z)(n,e);var t=(0,o.Z)(n);function n(e){var s;return(0,r.Z)(this,n),(s=t.call(this,e)).action=function(){s.setState({btnDisabled:!0}),s.props.restoreRepo()},s.state={btnDisabled:!1},s}return(0,s.Z)(n,[{key:"render",value:function(){var e=this.props.toggle;return(0,w.jsxs)(g.Z,{centered:!0,isOpen:!0,toggle:e,children:[(0,w.jsx)(v.Z,{toggle:e,children:(0,u.ih)("Restore Library")}),(0,w.jsx)(b.Z,{children:(0,w.jsx)("p",{children:(0,u.ih)("Are you sure you want to restore this library?")})}),(0,w.jsxs)(N.Z,{children:[(0,w.jsx)(k.Z,{color:"secondary",onClick:e,children:(0,u.ih)("Cancel")}),(0,w.jsx)(k.Z,{color:"primary",onClick:this.action,disabled:this.state.btnDisabled,children:(0,u.ih)("Restore")})]})]})}}]),n}(c.Component),y=(n(98391),n(53379),window.app.pageOptions),C=y.repoID,I=y.repoName,D=y.canRestoreRepo,F=y.commitID,M=y.commitTime,S=y.commitDesc,O=y.commitRelativeTime,P=y.showAuthor,R=y.authorAvatarURL,_=y.authorName,L=y.authorNickName,z=function(e){(0,a.Z)(n,e);var t=(0,o.Z)(n);function n(e){var s;return(0,r.Z)(this,n),(s=t.call(this,e)).toggleDialog=function(){s.setState({isConfirmDialogOpen:!s.state.isConfirmDialogOpen})},s.onSearchedClick=function(e){if(!0===e.is_dir){var t=u.ze+"library/"+e.repo_id+"/"+e.repo_name+e.path;(0,h.c4)(t,{repalce:!0})}else{var n=u.ze+"lib/"+e.repo_id+"/file"+d.c.encodePath(e.path);window.open("about:blank").location.href=n}},s.goBack=function(e){e.preventDefault(),window.history.back()},s.renderFolder=function(e){s.setState({folderPath:e,folderItems:[],isLoading:!0}),m.I.listCommitDir(C,F,e).then((function(e){s.setState({isLoading:!1,folderItems:e.data.dirent_list})})).catch((function(e){s.setState({isLoading:!1,errorMsg:d.c.getErrorMsg(e,!0)})}))},s.clickFolderPath=function(e,t){t.preventDefault(),s.renderFolder(e)},s.renderPath=function(){var e=s.state.folderPath,t=e.split("/");return"/"==e?(0,w.jsx)("span",{className:"text-truncate",title:I,children:I}):(0,w.jsxs)(c.Fragment,{children:[(0,w.jsx)("a",{href:"#",onClick:s.clickFolderPath.bind((0,i.Z)(s),"/"),className:"text-truncate",title:I,children:I}),(0,w.jsx)("span",{className:"mx-1",children:"/"}),t.map((function(e,n){return n>0&&n!=t.length-1?(0,w.jsxs)(c.Fragment,{children:[(0,w.jsx)("a",{href:"#",onClick:s.clickFolderPath.bind((0,i.Z)(s),t.slice(0,n+1).join("/")),className:"text-truncate",title:t[n],children:t[n]}),(0,w.jsx)("span",{className:"mx-1",children:"/"})]},n):null})),(0,w.jsx)("span",{className:"text-truncate",title:t[t.length-1],children:t[t.length-1]})]})},s.restoreRepo=function(){m.I.revertRepo(C,F).then((function(e){s.toggleDialog(),x.Z.success((0,u.ih)("Successfully restored the library."))})).catch((function(e){var t=d.c.getErrorMsg(e);s.toggleDialog(),x.Z.danger(t)}))},s.state={isLoading:!0,errorMsg:"",folderPath:"/",folderItems:[],isConfirmDialogOpen:!1},s}return(0,s.Z)(n,[{key:"componentDidMount",value:function(){this.renderFolder(this.state.folderPath)}},{key:"render",value:function(){var e=this.state,t=e.isConfirmDialogOpen,n=e.folderPath,r=(0,u.ih)("{placeholder} Snapshot");return r=r.replace("{placeholder}",'<span class="op-target text-truncate mx-1">'+d.c.HTMLescape(I)+"</span>"),(0,w.jsxs)(c.Fragment,{children:[(0,w.jsxs)("div",{className:"h-100 d-flex flex-column",children:[(0,w.jsxs)("div",{className:"top-header d-flex justify-content-between",children:[(0,w.jsx)("a",{href:u.ze,children:(0,w.jsx)("img",{src:u.si+u.j1,height:u.AN,width:u.Bv,title:u.y7,alt:"logo"})}),(0,w.jsx)(j.Z,{onSearchedClick:this.onSearchedClick})]}),(0,w.jsx)("div",{className:"flex-auto container-fluid pt-4 pb-6 o-auto",children:(0,w.jsx)("div",{className:"row",children:(0,w.jsxs)("div",{className:"col-md-10 offset-md-1",children:[(0,w.jsxs)("h2",{children:[(0,w.jsx)("span",{dangerouslySetInnerHTML:{__html:r},className:"d-flex mw-100"}),(0,w.jsxs)("span",{className:"heading-commit-time ml-1",children:["(",M,")"]})]}),(0,w.jsx)("a",{href:"#",className:"go-back",title:(0,u.ih)("Back"),role:"button","aria-label":(0,u.ih)("Back"),onClick:this.goBack,children:(0,w.jsx)("span",{className:"fas fa-chevron-left"})}),"/"==n&&(0,w.jsxs)("div",{className:"d-flex mb-2 align-items-center",children:[(0,w.jsx)("p",{className:"m-0 text-truncate",title:S,children:S}),(0,w.jsxs)("div",{className:"ml-4 border-left pl-4 d-flex align-items-center flex-shrink-0",children:[P?(0,w.jsxs)(c.Fragment,{children:[(0,w.jsx)("img",{src:R,width:"20",height:"20",alt:"",className:"rounded mr-1"}),(0,w.jsx)("a",{href:"".concat(u.ze,"profile/").concat(encodeURIComponent(_),"/"),children:L})]}):(0,w.jsx)("span",{children:(0,u.ih)("Unknown")}),(0,w.jsx)("p",{className:"m-0 ml-2",dangerouslySetInnerHTML:{__html:O}})]})]}),(0,w.jsxs)("div",{className:"d-flex justify-content-between align-items-center op-bar",children:[(0,w.jsxs)("p",{className:"m-0 text-truncate d-flex",children:[(0,w.jsx)("span",{className:"mr-1",children:(0,u.ih)("Current path: ")}),this.renderPath()]}),"/"==n&&D&&(0,w.jsx)("button",{className:"btn btn-secondary op-bar-btn flex-shrink-0 ml-4",onClick:this.toggleDialog,children:(0,u.ih)("Restore")})]}),(0,w.jsx)(U,{data:this.state,renderFolder:this.renderFolder})]})})})]}),t&&(0,w.jsx)(f.Z,{children:(0,w.jsx)(Z,{restoreRepo:this.restoreRepo,toggle:this.toggleDialog})})]})}}]),n}(c.Component),U=function(e){(0,a.Z)(n,e);var t=(0,o.Z)(n);function n(e){var s;return(0,r.Z)(this,n),(s=t.call(this,e)).theadData=[{width:"5%",text:""},{width:"55%",text:(0,u.ih)("Name")},{width:"20%",text:(0,u.ih)("Size")},{width:"20%",text:""}],s}return(0,s.Z)(n,[{key:"render",value:function(){var e=this,t=this.props.data,n=t.isLoading,r=t.errorMsg,s=t.folderPath,i=t.folderItems;return n?(0,w.jsx)(p.Z,{}):r?(0,w.jsx)("p",{className:"error mt-6 text-center",children:r}):(0,w.jsxs)("table",{className:"table-hover",children:[(0,w.jsx)("thead",{children:(0,w.jsx)("tr",{children:this.theadData.map((function(e,t){return(0,w.jsx)("th",{width:e.width,children:e.text},t)}))})}),(0,w.jsx)("tbody",{children:i.map((function(t,n){return(0,w.jsx)(B,{item:t,folderPath:s,renderFolder:e.props.renderFolder},n)}))})]})}}]),n}(c.Component),B=function(e){(0,a.Z)(n,e);var t=(0,o.Z)(n);function n(e){var s;return(0,r.Z)(this,n),(s=t.call(this,e)).handleMouseOver=function(){s.setState({isIconShown:!0})},s.handleMouseOut=function(){s.setState({isIconShown:!1})},s.restoreItem=function(e){e.preventDefault();var t=s.props.item,n=d.c.joinPath(s.props.folderPath,t.name);("dir"==t.type?m.I.revertFolder(C,n,F):m.I.revertFile(C,n,F)).then((function(e){x.Z.success((0,u.ih)("Successfully restored 1 item."))})).catch((function(e){var t=d.c.getErrorMsg(e);x.Z.danger(t)}))},s.renderFolder=function(e){e.preventDefault();var t=s.props.item,n=s.props.folderPath;s.props.renderFolder(d.c.joinPath(n,t.name))},s.state={isIconShown:!1},s}return(0,s.Z)(n,[{key:"render",value:function(){var e=this.props.item,t=this.state.isIconShown,n=this.props.folderPath;return"dir"==e.type?(0,w.jsxs)("tr",{onMouseOver:this.handleMouseOver,onMouseOut:this.handleMouseOut,onFocus:this.handleMouseOver,children:[(0,w.jsx)("td",{className:"text-center",children:(0,w.jsx)("img",{src:d.c.getFolderIconUrl(),alt:(0,u.ih)("Directory"),width:"24"})}),(0,w.jsx)("td",{children:(0,w.jsx)("a",{href:"#",onClick:this.renderFolder,children:e.name})}),(0,w.jsx)("td",{}),(0,w.jsx)("td",{children:(0,w.jsx)("a",{href:"#",className:"action-icon sf2-icon-reply ".concat(t?"":"invisible"),onClick:this.restoreItem,title:(0,u.ih)("Restore"),"aria-label":(0,u.ih)("Restore"),role:"button"})})]}):(0,w.jsxs)("tr",{onMouseOver:this.handleMouseOver,onMouseOut:this.handleMouseOut,onFocus:this.handleMouseOver,children:[(0,w.jsx)("td",{className:"text-center",children:(0,w.jsx)("img",{src:d.c.getFileIconUrl(e.name),alt:(0,u.ih)("File"),width:"24"})}),(0,w.jsx)("td",{children:(0,w.jsx)("a",{href:"".concat(u.ze,"repo/").concat(C,"/snapshot/files/?obj_id=").concat(e.obj_id,"&commit_id=").concat(F,"&p=").concat(encodeURIComponent(d.c.joinPath(n,e.name))),target:"_blank",rel:"noreferrer",children:e.name})}),(0,w.jsx)("td",{children:d.c.bytesToSize(e.size)}),(0,w.jsxs)("td",{children:[(0,w.jsx)("a",{href:"#",className:"action-icon sf2-icon-reply ".concat(t?"":"invisible"),onClick:this.restoreItem,title:(0,u.ih)("Restore"),"aria-label":(0,u.ih)("Restore"),role:"button"}),(0,w.jsx)("a",{href:"".concat(u.ze,"repo/").concat(C,"/").concat(e.obj_id,"/download/?file_name=").concat(encodeURIComponent(e.name),"&p=").concat(encodeURIComponent(d.c.joinPath(n,e.name))),className:"action-icon sf2-icon-download ".concat(t?"":"invisible"),title:(0,u.ih)("Download")})]})]})}}]),n}(c.Component);l.render((0,w.jsx)(z,{}),document.getElementById("wrapper"))}},function(e){e.O(0,[351],(function(){return t=47862,e(e.s=t);var t}));e.O()}]);