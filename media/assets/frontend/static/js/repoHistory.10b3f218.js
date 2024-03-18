"use strict";(self.webpackChunkseahub_frontend=self.webpackChunkseahub_frontend||[]).push([[718],{47276:function(e,t,i){i.d(t,{Z:function(){return b}});var a=i(15671),s=i(43144),n=i(60136),r=i(29388),o=i(47313),l=i(42995),c=i(12756),h=i(12213),d=i(70816),m=i.n(d),u=i(61805),p=i(4514),g=i(83854),f=i(51282),x=i(46417),D=function(e){(0,n.Z)(i,e);var t=(0,r.Z)(i);function i(e){var s;return(0,a.Z)(this,i),(s=t.call(this,e)).state={isLoading:!0,errorMsg:""},s}return(0,s.Z)(i,[{key:"componentDidMount",value:function(){var e=this,t=this.props,i=t.repoID,a=t.commitID;p.I.getCommitDetails(i,a).then((function(t){e.setState({isLoading:!1,errorMsg:"",commitDetails:t.data})})).catch((function(t){var i=g.c.getErrorMsg(t);e.setState({isLoading:!1,errorMsg:i})}))}},{key:"render",value:function(){var e=this.props,t=e.toggleDialog,i=e.commitTime;return(0,x.jsxs)(l.Z,{isOpen:!0,centered:!0,toggle:t,children:[(0,x.jsx)(c.Z,{toggle:t,children:(0,u.ih)("Modification Details")}),(0,x.jsxs)(h.Z,{children:[(0,x.jsx)("p",{className:"small",children:m()(i).format("YYYY-MM-DD HH:mm:ss")}),(0,x.jsx)(v,{data:this.state})]})]})}}]),i}(o.Component),v=function(e){(0,n.Z)(i,e);var t=(0,r.Z)(i);function i(){var e;(0,a.Z)(this,i);for(var s=arguments.length,n=new Array(s),r=0;r<s;r++)n[r]=arguments[r];return(e=t.call.apply(t,[this].concat(n))).renderDetails=function(e){for(var t=[{type:"new",title:(0,u.ih)("New files")},{type:"removed",title:(0,u.ih)("Deleted files")},{type:"renamed",title:(0,u.ih)("Renamed or Moved files")},{type:"modified",title:(0,u.ih)("Modified files")},{type:"newdir",title:(0,u.ih)("New directories")},{type:"deldir",title:(0,u.ih)("Deleted directories")}],i=!0,a=0,s=t.length;a<s;a++)if(e[t[a].type].length){i=!1;break}return i?(0,x.jsx)("p",{children:e.cmt_desc}):(0,x.jsx)(o.Fragment,{children:t.map((function(t,i){return e[t.type].length?(0,x.jsxs)(o.Fragment,{children:[(0,x.jsx)("h6",{children:t.title}),(0,x.jsx)("ul",{children:e[t.type].map((function(e,t){return(0,x.jsx)("li",{dangerouslySetInnerHTML:{__html:e},className:"commit-detail-item text-truncate"},t)}))})]},i):null}))})},e}return(0,s.Z)(i,[{key:"render",value:function(){var e=this.props.data,t=e.isLoading,i=e.errorMsg,a=e.commitDetails;return t?(0,x.jsx)(f.Z,{}):i?(0,x.jsx)("p",{className:"error mt-4 text-center",children:i}):this.renderDetails(a)}}]),i}(o.Component),b=D},98844:function(e,t,i){var a=i(15671),s=i(43144),n=i(60136),r=i(29388),o=i(47313),l=i(1168),c=i(3885),h=i(70816),d=i.n(h),m=i(83854),u=i(61805),p=i(4514),g=i(51282),f=i(9878),x=i(68164),D=i(24213),v=i(47276),b=i(42995),j=i(12756),P=i(12213),w=i(7764),C=i(58447),L=i(68396),Z=i(46417),M=function(e){(0,n.Z)(i,e);var t=(0,r.Z)(i);function i(e){var s;return(0,a.Z)(this,i),(s=t.call(this,e)).handleInputChange=function(e){s.setState({inputValue:e})},s.formSubmit=function(){var e=s.state.inputValue.map((function(e,t){return e.value})).join(","),t=s.props,i=t.repoID,a=t.commitID;s.setState({submitBtnDisabled:!0}),p.I.updateRepoCommitLabels(i,a,e).then((function(e){s.props.updateCommitLabels(e.data.revisionTags.map((function(e,t){return e.tag}))),s.props.toggleDialog(),L.Z.success((0,u.ih)("Successfully edited labels."))})).catch((function(e){var t=m.c.getErrorMsg(e);s.setState({formErrorMsg:t,submitBtnDisabled:!1})}))},s.state={inputValue:s.props.commitLabels.map((function(e,t){return{label:e,value:e}})),submitBtnDisabled:!1},s}return(0,s.Z)(i,[{key:"render",value:function(){var e=this.state.formErrorMsg;return(0,Z.jsxs)(b.Z,{isOpen:!0,centered:!0,toggle:this.props.toggleDialog,children:[(0,Z.jsx)(j.Z,{toggle:this.props.toggleDialog,children:(0,u.ih)("Edit labels")}),(0,Z.jsx)(P.Z,{children:(0,Z.jsxs)(o.Fragment,{children:[(0,Z.jsx)(C.Z,{defaultValue:this.props.commitLabels.map((function(e,t){return{label:e,value:e}})),isMulti:!0,onChange:this.handleInputChange,placeholder:""}),e&&(0,Z.jsx)("p",{className:"error m-0 mt-2",children:e})]})}),(0,Z.jsx)(w.Z,{children:(0,Z.jsx)("button",{className:"btn btn-primary",disabled:this.state.submitBtnDisabled,onClick:this.formSubmit,children:(0,u.ih)("Submit")})})]})}}]),i}(o.Component),y=M,N=(i(98391),i(53379),window.app.pageOptions),S=N.repoID,I=N.repoName,k=N.userPerm,O=N.showLabel,_=function(e){(0,n.Z)(i,e);var t=(0,r.Z)(i);function i(e){var s;return(0,a.Z)(this,i),(s=t.call(this,e)).getItems=function(e){p.I.getRepoHistory(S,e,s.state.perPage).then((function(t){s.setState({isLoading:!1,currentPage:e,items:t.data.data,hasNextPage:t.data.more})})).catch((function(e){s.setState({isLoading:!1,errorMsg:m.c.getErrorMsg(e,!0)})}))},s.resetPerPage=function(e){s.setState({perPage:e},(function(){s.getItems(1)}))},s.onSearchedClick=function(e){if(!0===e.is_dir){var t=u.ze+"library/"+e.repo_id+"/"+e.repo_name+e.path;(0,c.c4)(t,{repalce:!0})}else{var i=u.ze+"lib/"+e.repo_id+"/file"+m.c.encodePath(e.path);window.open("about:blank").location.href=i}},s.goBack=function(e){e.preventDefault(),window.history.back()},s.state={isLoading:!0,errorMsg:"",currentPage:1,perPage:25,hasNextPage:!1,items:[]},s}return(0,s.Z)(i,[{key:"componentDidMount",value:function(){var e=this,t=new URL(window.location).searchParams,i=this.state,a=i.currentPage,s=i.perPage;this.setState({perPage:parseInt(t.get("per_page")||s),currentPage:parseInt(t.get("page")||a)},(function(){e.getItems(e.state.currentPage)}))}},{key:"render",value:function(){var e=(0,u.ih)("{placeholder} Modification History");return e=e.replace("{placeholder}",'<span class="op-target text-truncate mx-1">'+m.c.HTMLescape(I)+"</span>"),(0,Z.jsx)(o.Fragment,{children:(0,Z.jsxs)("div",{className:"h-100 d-flex flex-column",children:[(0,Z.jsxs)("div",{className:"top-header d-flex justify-content-between",children:[(0,Z.jsx)("a",{href:u.ze,children:(0,Z.jsx)("img",{src:u.si+u.j1,height:u.AN,width:u.Bv,title:u.y7,alt:"logo"})}),(0,Z.jsx)(D.Z,{onSearchedClick:this.onSearchedClick})]}),(0,Z.jsx)("div",{className:"flex-auto container-fluid pt-4 pb-6 o-auto",children:(0,Z.jsx)("div",{className:"row",children:(0,Z.jsxs)("div",{className:"col-md-10 offset-md-1",children:[(0,Z.jsx)("h2",{dangerouslySetInnerHTML:{__html:e},className:"d-flex text-nowrap"}),(0,Z.jsx)("a",{href:"#",className:"go-back",title:(0,u.ih)("Back"),onClick:this.goBack,role:"button","aria-label":(0,u.ih)("Back"),children:(0,Z.jsx)("span",{className:"fas fa-chevron-left"})}),"rw"==k&&(0,Z.jsx)("p",{className:"tip",children:(0,u.ih)("Tip: a snapshot will be generated after modification, which records the library state after the modification.")}),(0,Z.jsx)(B,{isLoading:this.state.isLoading,errorMsg:this.state.errorMsg,items:this.state.items,currentPage:this.state.currentPage,hasNextPage:this.state.hasNextPage,curPerPage:this.state.perPage,resetPerPage:this.resetPerPage,getListByPage:this.getItems})]})})})]})})}}]),i}(o.Component),B=function(e){(0,n.Z)(i,e);var t=(0,r.Z)(i);function i(e){var s;return(0,a.Z)(this,i),(s=t.call(this,e)).getPreviousPage=function(){s.props.getListByPage(s.props.currentPage-1)},s.getNextPage=function(){s.props.getListByPage(s.props.currentPage+1)},s.theadData=O?[{width:"43%",text:(0,u.ih)("Description")},{width:"12%",text:(0,u.ih)("Time")},{width:"9%",text:(0,u.ih)("Modifier")},{width:"12%",text:"".concat((0,u.ih)("Device")," / ").concat((0,u.ih)("Version"))},{width:"12%",text:(0,u.ih)("Labels")},{width:"12%",text:""}]:[{width:"43%",text:(0,u.ih)("Description")},{width:"15%",text:(0,u.ih)("Time")},{width:"15%",text:(0,u.ih)("Modifier")},{width:"15%",text:"".concat((0,u.ih)("Device")," / ").concat((0,u.ih)("Version"))},{width:"12%",text:""}],s}return(0,s.Z)(i,[{key:"render",value:function(){var e=this.props,t=e.isLoading,i=e.errorMsg,a=e.items,s=e.curPerPage,n=e.currentPage,r=e.hasNextPage;return t?(0,Z.jsx)(g.Z,{}):i?(0,Z.jsx)("p",{className:"error mt-6 text-center",children:i}):(0,Z.jsxs)(o.Fragment,{children:[(0,Z.jsxs)("table",{className:"table-hover",children:[(0,Z.jsx)("thead",{children:(0,Z.jsx)("tr",{children:this.theadData.map((function(e,t){return(0,Z.jsx)("th",{width:e.width,children:e.text},t)}))})}),(0,Z.jsx)("tbody",{children:a.map((function(e,t){return e.isFirstCommit=1==n&&0==t,e.showDetails=r||t!=a.length-1,(0,Z.jsx)(E,{item:e},t)}))})]}),(0,Z.jsx)(f.Z,{gotoPreviousPage:this.getPreviousPage,gotoNextPage:this.getNextPage,currentPage:n,hasNextPage:r,curPerPage:s,resetPerPage:this.props.resetPerPage})]})}}]),i}(o.Component),E=function(e){(0,n.Z)(i,e);var t=(0,r.Z)(i);function i(e){var s;return(0,a.Z)(this,i),(s=t.call(this,e)).handleMouseOver=function(){s.setState({isIconShown:!0})},s.handleMouseOut=function(){s.setState({isIconShown:!1})},s.showCommitDetails=function(e){e.preventDefault(),s.setState({isCommitDetailsDialogOpen:!s.state.isCommitDetailsDialogOpen})},s.toggleCommitDetailsDialog=function(){s.setState({isCommitDetailsDialogOpen:!s.state.isCommitDetailsDialogOpen})},s.editLabel=function(e){e.preventDefault(),s.setState({isCommitLabelUpdateDialogOpen:!s.state.isCommitLabelUpdateDialogOpen})},s.toggleLabelEditDialog=function(){s.setState({isCommitLabelUpdateDialogOpen:!s.state.isCommitLabelUpdateDialogOpen})},s.updateLabels=function(e){s.setState({labels:e})},s.state={labels:s.props.item.tags,isIconShown:!1,isCommitLabelUpdateDialogOpen:!1,isCommitDetailsDialogOpen:!1},s}return(0,s.Z)(i,[{key:"render",value:function(){var e=this.props.item,t=this.state,i=t.isIconShown,a=t.isCommitLabelUpdateDialogOpen,s=t.isCommitDetailsDialogOpen,n=t.labels,r="";return r=e.email?e.second_parent_id?(0,u.ih)("None"):(0,Z.jsx)("a",{href:"".concat(u.ze,"profile/").concat(encodeURIComponent(e.email),"/"),children:e.name}):(0,u.ih)("Unknown"),(0,Z.jsxs)(o.Fragment,{children:[(0,Z.jsxs)("tr",{onMouseOver:this.handleMouseOver,onMouseOut:this.handleMouseOut,onFocus:this.handleMouseOver,children:[(0,Z.jsxs)("td",{children:[e.description,e.showDetails&&(0,Z.jsx)("a",{href:"#",className:"details",onClick:this.showCommitDetails,role:"button",children:(0,u.ih)("Details")})]}),(0,Z.jsx)("td",{title:d()(e.time).format("LLLL"),children:d()(e.time).format("YYYY-MM-DD")}),(0,Z.jsx)("td",{children:r}),(0,Z.jsx)("td",{children:e.client_version?"".concat(e.device_name," / ").concat(e.client_version):"API / --"}),O&&(0,Z.jsxs)("td",{children:[n.map((function(e,t){return(0,Z.jsx)("span",{className:"commit-label",children:e},t)})),"rw"==k&&(0,Z.jsx)("a",{href:"#",role:"button",className:"attr-action-icon fa fa-pencil-alt ".concat(i?"":"invisible"),title:(0,u.ih)("Edit"),"aria-label":(0,u.ih)("Edit"),onClick:this.editLabel})]}),(0,Z.jsx)("td",{children:"rw"==k&&(e.isFirstCommit?(0,Z.jsx)("span",{className:i?"":"invisible",children:(0,u.ih)("Current Version")}):(0,Z.jsx)("a",{href:"".concat(u.ze,"repo/").concat(S,"/snapshot/?commit_id=").concat(e.commit_id),className:i?"":"invisible",children:(0,u.ih)("View Snapshot")}))})]}),s&&(0,Z.jsx)(x.Z,{children:(0,Z.jsx)(v.Z,{repoID:S,commitID:e.commit_id,commitTime:e.time,toggleDialog:this.toggleCommitDetailsDialog})}),a&&(0,Z.jsx)(x.Z,{children:(0,Z.jsx)(y,{repoID:S,commitID:e.commit_id,commitLabels:n,updateCommitLabels:this.updateLabels,toggleDialog:this.toggleLabelEditDialog})})]})}}]),i}(o.Component);l.render((0,Z.jsx)(_,{}),document.getElementById("wrapper"))}},function(e){e.O(0,[351],(function(){return t=98844,e(e.s=t);var t}));e.O()}]);