(this["webpackJsonpseahub-frontend"]=this["webpackJsonpseahub-frontend"]||[]).push([[15],{1731:function(e,t,a){a(75),e.exports=a(1760)},1732:function(e,t,a){},1760:function(e,t,a){"use strict";a.r(t);var i=a(3),s=a(5),n=a(7),c=a(6),r=a(2),o=a.n(r),l=a(31),b=a.n(l),d=a(21),h=a(12),m=a.n(h),j=a(4),u=a(1),g=a(8),p=a(19),O=a(48),f=a(23),x=a(69),v=a(376),D=a(108),P=a(96),w=a(97),C=a(131),L=a(299),M=a(10),N=a(0),y=function(e){Object(n.a)(a,e);var t=Object(c.a)(a);function a(e){var s;return Object(i.a)(this,a),(s=t.call(this,e)).handleInputChange=function(e){s.setState({inputValue:e})},s.formSubmit=function(){var e=s.state.inputValue.map((function(e,t){return e.value})).join(","),t=s.props,a=t.repoID,i=t.commitID;s.setState({submitBtnDisabled:!0}),g.a.updateRepoCommitLabels(a,i,e).then((function(e){s.props.updateCommitLabels(e.data.revisionTags.map((function(e,t){return e.tag}))),s.props.toggleDialog(),M.a.success(Object(u.tb)("Successfully edited labels."))})).catch((function(e){var t=j.a.getErrorMsg(e);s.setState({formErrorMsg:t,submitBtnDisabled:!1})}))},s.state={inputValue:s.props.commitLabels.map((function(e,t){return{label:e,value:e}})),submitBtnDisabled:!1},s}return Object(s.a)(a,[{key:"render",value:function(){var e=this.state.formErrorMsg;return Object(N.jsxs)(D.a,{isOpen:!0,centered:!0,toggle:this.props.toggleDialog,children:[Object(N.jsx)(P.a,{toggle:this.props.toggleDialog,children:Object(u.tb)("Edit labels")}),Object(N.jsx)(w.a,{children:Object(N.jsxs)(o.a.Fragment,{children:[Object(N.jsx)(L.a,{defaultValue:this.props.commitLabels.map((function(e,t){return{label:e,value:e}})),isMulti:!0,onChange:this.handleInputChange,placeholder:""}),e&&Object(N.jsx)("p",{className:"error m-0 mt-2",children:e})]})}),Object(N.jsx)(C.a,{children:Object(N.jsx)("button",{className:"btn btn-primary",disabled:this.state.submitBtnDisabled,onClick:this.formSubmit,children:Object(u.tb)("Submit")})})]})}}]),a}(o.a.Component),S=(a(152),a(170),a(1732),window.app.pageOptions),k=S.repoID,I=S.repoName,_=S.userPerm,B=S.showLabel,E=function(e){Object(n.a)(a,e);var t=Object(c.a)(a);function a(e){var s;return Object(i.a)(this,a),(s=t.call(this,e)).getItems=function(e){g.a.getRepoHistory(k,e,s.state.perPage).then((function(t){s.setState({isLoading:!1,currentPage:e,items:t.data.data,hasNextPage:t.data.more})})).catch((function(e){s.setState({isLoading:!1,errorMsg:j.a.getErrorMsg(e,!0)})}))},s.resetPerPage=function(e){s.setState({perPage:e},(function(){s.getItems(1)}))},s.onSearchedClick=function(e){if(!0===e.is_dir){var t=u.vc+"library/"+e.repo_id+"/"+e.repo_name+e.path;Object(d.c)(t,{repalce:!0})}else{var a=u.vc+"lib/"+e.repo_id+"/file"+j.a.encodePath(e.path);window.open("about:blank").location.href=a}},s.goBack=function(e){e.preventDefault(),window.history.back()},s.state={isLoading:!0,errorMsg:"",currentPage:1,perPage:25,hasNextPage:!1,items:[]},s}return Object(s.a)(a,[{key:"componentDidMount",value:function(){var e=this,t=new URL(window.location).searchParams,a=this.state,i=a.currentPage,s=a.perPage;this.setState({perPage:parseInt(t.get("per_page")||s),currentPage:parseInt(t.get("page")||i)},(function(){e.getItems(e.state.currentPage)}))}},{key:"render",value:function(){return Object(N.jsx)(o.a.Fragment,{children:Object(N.jsxs)("div",{className:"h-100 d-flex flex-column",children:[Object(N.jsxs)("div",{className:"top-header d-flex justify-content-between",children:[Object(N.jsx)("a",{href:u.vc,children:Object(N.jsx)("img",{src:u.Rb+u.Mb,height:u.Lb,width:u.Nb,title:u.wc,alt:"logo"})}),Object(N.jsx)(x.a,{onSearchedClick:this.onSearchedClick})]}),Object(N.jsx)("div",{className:"flex-auto container-fluid pt-4 pb-6 o-auto",children:Object(N.jsx)("div",{className:"row",children:Object(N.jsxs)("div",{className:"col-md-10 offset-md-1",children:[Object(N.jsx)("h2",{children:j.a.generateDialogTitle(Object(u.tb)("{placeholder} Modification History"),I)}),Object(N.jsx)("a",{href:"#",className:"go-back",title:Object(u.tb)("Back"),onClick:this.goBack,role:"button","aria-label":Object(u.tb)("Back"),children:Object(N.jsx)("span",{className:"fas fa-chevron-left"})}),"rw"==_&&Object(N.jsx)("p",{className:"tip",children:Object(u.tb)("Tip: a snapshot will be generated after modification, which records the library state after the modification.")}),Object(N.jsx)(F,{isLoading:this.state.isLoading,errorMsg:this.state.errorMsg,items:this.state.items,currentPage:this.state.currentPage,hasNextPage:this.state.hasNextPage,curPerPage:this.state.perPage,resetPerPage:this.resetPerPage,getListByPage:this.getItems})]})})})]})})}}]),a}(o.a.Component),F=function(e){Object(n.a)(a,e);var t=Object(c.a)(a);function a(e){var s;return Object(i.a)(this,a),(s=t.call(this,e)).getPreviousPage=function(){s.props.getListByPage(s.props.currentPage-1)},s.getNextPage=function(){s.props.getListByPage(s.props.currentPage+1)},s.theadData=B?[{width:"43%",text:Object(u.tb)("Description")},{width:"12%",text:Object(u.tb)("Time")},{width:"9%",text:Object(u.tb)("Modifier")},{width:"12%",text:"".concat(Object(u.tb)("Device")," / ").concat(Object(u.tb)("Version"))},{width:"12%",text:Object(u.tb)("Labels")},{width:"12%",text:""}]:[{width:"43%",text:Object(u.tb)("Description")},{width:"15%",text:Object(u.tb)("Time")},{width:"15%",text:Object(u.tb)("Modifier")},{width:"15%",text:"".concat(Object(u.tb)("Device")," / ").concat(Object(u.tb)("Version"))},{width:"12%",text:""}],s}return Object(s.a)(a,[{key:"render",value:function(){var e=this.props,t=e.isLoading,a=e.errorMsg,i=e.items,s=e.curPerPage,n=e.currentPage,c=e.hasNextPage;return t?Object(N.jsx)(p.a,{}):a?Object(N.jsx)("p",{className:"error mt-6 text-center",children:a}):Object(N.jsxs)(o.a.Fragment,{children:[Object(N.jsxs)("table",{className:"table-hover",children:[Object(N.jsx)("thead",{children:Object(N.jsx)("tr",{children:this.theadData.map((function(e,t){return Object(N.jsx)("th",{width:e.width,children:e.text},t)}))})}),Object(N.jsx)("tbody",{children:i.map((function(e,t){return e.isFirstCommit=1==n&&0==t,e.showDetails=c||t!=i.length-1,Object(N.jsx)(T,{item:e},t)}))})]}),Object(N.jsx)(O.a,{gotoPreviousPage:this.getPreviousPage,gotoNextPage:this.getNextPage,currentPage:n,hasNextPage:c,curPerPage:s,resetPerPage:this.props.resetPerPage})]})}}]),a}(o.a.Component),T=function(e){Object(n.a)(a,e);var t=Object(c.a)(a);function a(e){var s;return Object(i.a)(this,a),(s=t.call(this,e)).handleMouseOver=function(){s.setState({isIconShown:!0})},s.handleMouseOut=function(){s.setState({isIconShown:!1})},s.showCommitDetails=function(e){e.preventDefault(),s.setState({isCommitDetailsDialogOpen:!s.state.isCommitDetailsDialogOpen})},s.toggleCommitDetailsDialog=function(){s.setState({isCommitDetailsDialogOpen:!s.state.isCommitDetailsDialogOpen})},s.editLabel=function(e){e.preventDefault(),s.setState({isCommitLabelUpdateDialogOpen:!s.state.isCommitLabelUpdateDialogOpen})},s.toggleLabelEditDialog=function(){s.setState({isCommitLabelUpdateDialogOpen:!s.state.isCommitLabelUpdateDialogOpen})},s.updateLabels=function(e){s.setState({labels:e})},s.state={labels:s.props.item.tags,isIconShown:!1,isCommitLabelUpdateDialogOpen:!1,isCommitDetailsDialogOpen:!1},s}return Object(s.a)(a,[{key:"render",value:function(){var e=this.props.item,t=this.state,a=t.isIconShown,i=t.isCommitLabelUpdateDialogOpen,s=t.isCommitDetailsDialogOpen,n=t.labels,c="";return c=e.email?e.second_parent_id?Object(u.tb)("None"):Object(N.jsx)("a",{href:"".concat(u.vc,"profile/").concat(encodeURIComponent(e.email),"/"),children:e.name}):Object(u.tb)("Unknown"),Object(N.jsxs)(o.a.Fragment,{children:[Object(N.jsxs)("tr",{onMouseOver:this.handleMouseOver,onMouseOut:this.handleMouseOut,onFocus:this.handleMouseOver,children:[Object(N.jsxs)("td",{children:[e.description,e.showDetails&&Object(N.jsx)("a",{href:"#",className:"details",onClick:this.showCommitDetails,role:"button",children:Object(u.tb)("Details")})]}),Object(N.jsx)("td",{title:m()(e.time).format("LLLL"),children:m()(e.time).format("YYYY-MM-DD")}),Object(N.jsx)("td",{children:c}),Object(N.jsx)("td",{children:e.client_version?"".concat(e.device_name," / ").concat(e.client_version):"API / --"}),B&&Object(N.jsxs)("td",{children:[n.map((function(e,t){return Object(N.jsx)("span",{className:"commit-label",children:e},t)})),"rw"==_&&Object(N.jsx)("a",{href:"#",role:"button",className:"attr-action-icon fa fa-pencil-alt ".concat(a?"":"invisible"),title:Object(u.tb)("Edit"),"aria-label":Object(u.tb)("Edit"),onClick:this.editLabel})]}),Object(N.jsx)("td",{children:"rw"==_&&(e.isFirstCommit?Object(N.jsx)("span",{className:a?"":"invisible",children:Object(u.tb)("Current Version")}):Object(N.jsx)("a",{href:"".concat(u.vc,"repo/").concat(k,"/snapshot/?commit_id=").concat(e.commit_id),className:a?"":"invisible",children:Object(u.tb)("View Snapshot")}))})]}),s&&Object(N.jsx)(f.a,{children:Object(N.jsx)(v.a,{repoID:k,commitID:e.commit_id,commitTime:e.time,toggleDialog:this.toggleCommitDetailsDialog})}),i&&Object(N.jsx)(f.a,{children:Object(N.jsx)(y,{repoID:k,commitID:e.commit_id,commitLabels:n,updateCommitLabels:this.updateLabels,toggleDialog:this.toggleLabelEditDialog})})]})}}]),a}(o.a.Component);b.a.render(Object(N.jsx)(E,{}),document.getElementById("wrapper"))},376:function(e,t,a){"use strict";var i=a(3),s=a(5),n=a(7),c=a(6),r=a(2),o=a.n(r),l=a(108),b=a(96),d=a(97),h=a(12),m=a.n(h),j=a(1),u=a(8),g=a(4),p=a(19),O=(a(551),a(0)),f=function(e){Object(n.a)(a,e);var t=Object(c.a)(a);function a(e){var s;return Object(i.a)(this,a),(s=t.call(this,e)).state={isLoading:!0,errorMsg:""},s}return Object(s.a)(a,[{key:"componentDidMount",value:function(){var e=this,t=this.props,a=t.repoID,i=t.commitID;u.a.getCommitDetails(a,i).then((function(t){e.setState({isLoading:!1,errorMsg:"",commitDetails:t.data})})).catch((function(t){var a=g.a.getErrorMsg(t);e.setState({isLoading:!1,errorMsg:a})}))}},{key:"render",value:function(){var e=this.props,t=e.toggleDialog;e.commitTime;return Object(O.jsxs)(l.a,{isOpen:!0,centered:!0,toggle:t,children:[Object(O.jsx)(b.a,{toggle:t,children:Object(j.tb)("Modification Details")}),Object(O.jsxs)(d.a,{children:[Object(O.jsx)("p",{className:"small",children:m()(this.props.commitTime).format("YYYY-MM-DD HH:mm:ss")}),Object(O.jsx)(x,{data:this.state})]})]})}}]),a}(o.a.Component),x=function(e){Object(n.a)(a,e);var t=Object(c.a)(a);function a(){var e;Object(i.a)(this,a);for(var s=arguments.length,n=new Array(s),c=0;c<s;c++)n[c]=arguments[c];return(e=t.call.apply(t,[this].concat(n))).renderDetails=function(e){for(var t=[{type:"new",title:Object(j.tb)("New files")},{type:"removed",title:Object(j.tb)("Deleted files")},{type:"renamed",title:Object(j.tb)("Renamed or Moved files")},{type:"modified",title:Object(j.tb)("Modified files")},{type:"newdir",title:Object(j.tb)("New directories")},{type:"deldir",title:Object(j.tb)("Deleted directories")}],a=!0,i=0,s=t.length;i<s;i++)if(e[t[i].type].length){a=!1;break}return a?Object(O.jsx)("p",{children:e.cmt_desc}):Object(O.jsx)(o.a.Fragment,{children:t.map((function(t,a){if(e[t.type].length)return Object(O.jsxs)(o.a.Fragment,{children:[Object(O.jsx)("h6",{children:t.title}),Object(O.jsx)("ul",{children:e[t.type].map((function(e,t){return Object(O.jsx)("li",{dangerouslySetInnerHTML:{__html:e},className:"commit-detail-item"},t)}))})]},a)}))})},e}return Object(s.a)(a,[{key:"render",value:function(){var e=this.props.data,t=e.isLoading,a=e.errorMsg,i=e.commitDetails;return t?Object(O.jsx)(p.a,{}):a?Object(O.jsx)("p",{className:"error mt-4 text-center",children:a}):this.renderDetails(i)}}]),a}(o.a.Component);t.a=f},551:function(e,t,a){}},[[1731,1,0]]]);
//# sourceMappingURL=repoHistory.chunk.js.map