"use strict";(self.webpackChunkseahub_frontend=self.webpackChunkseahub_frontend||[]).push([[53],{66554:function(e,t,n){var i=n(15671),s=n(43144),o=n(60136),r=n(29388),a=n(47313),l=n(1168),c=n(35662),h=n(61805),d=n(93433),u=n(14658),m=n(51282),p=n(70816),f=n.n(p),g=n(13380),v=n(25417),I=n(72611),k=n(57124),x=n(52522),C=(n(23534),n(46417));f().locale(window.app.config.lang);var w=function(e){(0,o.Z)(n,e);var t=(0,r.Z)(n);function n(e){var s;return(0,i.Z)(this,n),(s=t.call(this,e)).onMouseEnter=function(){s.props.isItemFreezed||s.setState({isShowOperationIcon:!0})},s.onMouseLeave=function(){s.props.isItemFreezed||s.setState({isShowOperationIcon:!1})},s.onToggleClick=function(e){s.setState({isMenuShow:!s.state.isMenuShow}),s.props.onFreezedItemToggle()},s.onItemClick=function(){if(s.setState({isShowOperationIcon:!1}),s.props.item.commit_id!==s.props.currentItem.commit_id){var e=s.props.index;s.props.onItemClick(s.props.item,e)}},s.onItemRestore=function(){s.props.onItemRestore(s.props.currentItem)},s.onItemDownload=function(){},s.state={isShowOperationIcon:!1,isMenuShow:!1},s}return(0,s.Z)(n,[{key:"render",value:function(){if(!this.props.currentItem)return"";var e=this.props.item,t=f()(e.ctime).format("YYYY-MM-DD HH:mm"),n=!1;this.props.item&&this.props.currentItem&&(n=this.props.item.commit_id===this.props.currentItem.commit_id);var i=this.props.currentItem.rev_file_id,s=x.Z.getUrl({type:"download_historic_file",filePath:h.bc,objID:i});return(0,C.jsxs)("li",{className:"history-list-item ".concat(n?"item-active":""),onMouseEnter:this.onMouseEnter,onMouseLeave:this.onMouseLeave,onClick:this.onItemClick,children:[(0,C.jsxs)("div",{className:"history-info",children:[(0,C.jsx)("div",{className:"time",children:t}),(0,C.jsxs)("div",{className:"owner",children:[(0,C.jsx)("span",{className:"squire-icon"}),(0,C.jsx)("span",{children:e.creator_name})]})]}),(0,C.jsx)("div",{className:"history-operation",children:(0,C.jsxs)(g.Z,{isOpen:this.state.isMenuShow,toggle:this.onToggleClick,children:[(0,C.jsx)(v.Z,{tag:"a",className:"fas fa-ellipsis-v ".concat(this.state.isShowOperationIcon||n?"":"invisible"),"data-toggle":"dropdown","aria-expanded":this.state.isMenuShow,title:(0,h.ih)("More operations"),"aria-label":(0,h.ih)("More operations")}),(0,C.jsxs)(I.Z,{children:[0!==this.props.index&&(0,C.jsx)(k.Z,{onClick:this.onItemRestore,children:(0,h.ih)("Restore")}),(0,C.jsx)(k.Z,{tag:"a",href:s,onClick:this.onItemDownLoad,children:(0,h.ih)("Download")})]})]})})]})}}]),n}(a.Component),y=function(e){(0,o.Z)(n,e);var t=(0,r.Z)(n);function n(e){var s;return(0,i.Z)(this,n),(s=t.call(this,e)).componentDidMount=function(){var e=s.props.historyList;e.length>0&&(s.setState({currentItem:e[0]}),1===e?s.props.onItemClick(e[0]):s.props.onItemClick(e[0],e[1]))},s.onFreezedItemToggle=function(){s.setState({isItemFreezed:!s.state.isItemFreezed})},s.onScrollHandler=function(e){var t=e.target.clientHeight,n=e.target.scrollHeight,i=t+e.target.scrollTop+1>=n,o=s.props.hasMore;i&&o&&s.props.reloadMore()},s.onItemClick=function(e,t){if(s.setState({currentItem:e}),t!==s.props.historyList.length){var n=s.props.historyList[t+1];s.props.onItemClick(e,n)}else s.props.onItemClick(e)},s.state={isItemFreezed:!1,currentItem:null},s}return(0,s.Z)(n,[{key:"render",value:function(){var e=this;return(0,C.jsxs)("ul",{className:"history-list-container",onScroll:this.onScrollHandler,children:[this.props.historyList.map((function(t,n){return(0,C.jsx)(w,{item:t,index:n,currentItem:e.state.currentItem,isItemFreezed:e.state.isItemFreezed,onItemClick:e.onItemClick,onItemRestore:e.props.onItemRestore,onFreezedItemToggle:e.onFreezedItemToggle},n)})),this.props.isReloadingData&&(0,C.jsx)("li",{children:(0,C.jsx)(m.Z,{})})]})}}]),n}(a.Component),Z=n(68396),j=function(e){(0,o.Z)(n,e);var t=(0,r.Z)(n);function n(e){var s;return(0,i.Z)(this,n),(s=t.call(this,e)).reloadMore=function(){if(!s.state.isReloadingData){var e=s.state.currentPage+1;s.setState({currentPage:e,isReloadingData:!0}),u.Z.listFileHistoryRecords(h.bc,e,h.LZ).then((function(e){s.updateResultState(e.data),s.setState({isReloadingData:!1})}))}},s.onItemRestore=function(e){var t=e.commit_id;u.Z.revertFile(h.bc,t).then((function(e){e.data.success&&(s.setState({isLoading:!0}),s.refershFileList());var t=(0,h.ih)("Successfully restored.");Z.Z.success(t)}))},s.onItemClick=function(e,t){s.props.onItemClick(e,t)},s.state={historyInfo:"",currentPage:1,hasMore:!1,isLoading:!0,isError:!1,fileOwner:"",isReloadingData:!1},s}return(0,s.Z)(n,[{key:"componentDidMount",value:function(){var e=this;u.Z.listFileHistoryRecords(h.bc,1,h.LZ).then((function(t){if(0===t.data.length)throw e.setState({isLoading:!1}),Error("there has an error in server");e.initResultState(t.data)}))}},{key:"refershFileList",value:function(){var e=this;u.Z.listFileHistoryRecords(h.bc,1,h.LZ).then((function(t){e.initResultState(t.data)}))}},{key:"initResultState",value:function(e){e.data.length&&this.setState({historyInfo:e.data,currentPage:e.page,hasMore:e.total_count>h.LZ*this.state.currentPage,isLoading:!1,isError:!1,fileOwner:e.data[0].creator_email})}},{key:"updateResultState",value:function(e){e.data.length&&this.setState({historyInfo:[].concat((0,d.Z)(this.state.historyInfo),(0,d.Z)(e.data)),currentPage:e.page,hasMore:e.total_count>h.LZ*this.state.currentPage,isLoading:!1,isError:!1,fileOwner:e.data[0].creator_email})}},{key:"render",value:function(){return(0,C.jsx)("div",{className:"side-panel history-side-panel",children:(0,C.jsxs)("div",{className:"side-panel-center",children:[(0,C.jsx)("div",{className:"history-side-panel-title",children:(0,h.ih)("History Versions")}),(0,C.jsxs)("div",{className:"history-body",children:[this.state.isLoading&&(0,C.jsx)(m.Z,{}),this.state.historyInfo&&(0,C.jsx)(y,{hasMore:this.state.hasMore,isReloadingData:this.state.isReloadingData,historyList:this.state.historyInfo,reloadMore:this.reloadMore,onItemClick:this.onItemClick,onItemRestore:this.onItemRestore})]})]})})}}]),n}(a.Component),M=n(95423),S=function(e){(0,o.Z)(n,e);var t=(0,r.Z)(n);function n(){var e;(0,i.Z)(this,n);for(var s=arguments.length,o=new Array(s),r=0;r<s;r++)o[r]=arguments[r];return(e=t.call.apply(t,[this].concat(o))).onSearchedClick=function(){},e}return(0,s.Z)(n,[{key:"render",value:function(){var e=this.props,t=e.renderingContent,n=e.newMarkdownContent;return(0,C.jsxs)("div",{className:"content-viewer flex-fill",children:[t&&(0,C.jsx)(m.Z,{}),!t&&(0,C.jsx)(M.MarkdownViewer,{isFetching:t,value:n,isShowOutline:!1,mathJaxSource:h.si+"js/mathjax/tex-svg.js"})]})}}]),n}(a.Component),R=S,L=n(4514),F=(n(54890),function(e){(0,o.Z)(n,e);var t=(0,r.Z)(n);function n(e){var s;return(0,i.Z)(this,n),(s=t.call(this,e)).setDiffContent=function(e,t){s.setState({renderingContent:!1,newMarkdownContent:e,oldMarkdownContent:t})},s.onHistoryItemClick=function(e,t){s.setState({renderingContent:!0}),L.I.getFileRevision(h.y8,e.commit_id,e.path).then((function(e){c.Z.all([L.I.getFileContent(e.data)]).then(c.Z.spread((function(e){s.setDiffContent(e.data,"")})))}))},s.onBackClick=function(e){e.preventDefault(),window.history.back()},s.state={renderingContent:!0,newMarkdownContent:"",oldMarkdownContent:""},s}return(0,s.Z)(n,[{key:"render",value:function(){return(0,C.jsxs)("div",{className:"history-content flex-fill d-flex h-100",children:[(0,C.jsxs)("div",{className:"flex-fill d-flex flex-column text-truncate",children:[(0,C.jsx)("div",{className:"history-header file-history-header flex-shrink-0",children:(0,C.jsxs)("div",{className:"title d-flex mw-100",children:[(0,C.jsx)("a",{href:"#",className:"go-back",title:"Back",onClick:this.onBackClick,children:(0,C.jsx)("span",{className:"fas fa-chevron-left"})}),(0,C.jsx)("span",{className:"name text-truncate",title:h.Yp,children:h.Yp})]})}),(0,C.jsx)(R,{newMarkdownContent:this.state.newMarkdownContent,oldMarkdownContent:this.state.oldMarkdownContent,renderingContent:this.state.renderingContent})]}),(0,C.jsx)(j,{onItemClick:this.onHistoryItemClick})]})}}]),n}(a.Component));l.render((0,C.jsx)(F,{}),document.getElementById("wrapper"))},23534:function(){}},function(e){e.O(0,[351],(function(){return t=66554,e(e.s=t);var t}));e.O()}]);