"use strict";(self.webpackChunkseahub_frontend=self.webpackChunkseahub_frontend||[]).push([[840],{80015:function(e,t,n){var r=n(15671),s=n(43144),i=n(60136),o=n(29388),a=n(47313),c=n(1168),u=n(4514),f=n(61805),d=n(38130),p=n(15254),h=n(51282),l=n(17008),v=(n(88892),n(46417)),g=window.app.pageOptions,m=g.repoID,Z=g.filePath,w=g.err,j=g.commitID,k=g.fileType,x=function(e){(0,i.Z)(n,e);var t=(0,o.Z)(n);function n(){return(0,r.Z)(this,n),t.apply(this,arguments)}return(0,s.Z)(n,[{key:"render",value:function(){return(0,v.jsx)(d.Z,{content:(0,v.jsx)(y,{})})}}]),n}(a.Component),y=function(e){(0,i.Z)(n,e);var t=(0,o.Z)(n);function n(e){var s;return(0,r.Z)(this,n),(s=t.call(this,e)).state={isLoading:!w,errorMsg:""},s}return(0,s.Z)(n,[{key:"componentDidMount",value:function(){var e=this;if(!w){!function t(){u.I.queryOfficeFileConvertStatus(m,j,Z,k.toLowerCase()).then((function(n){switch(n.data.status){case"PROCESSING":e.setState({isLoading:!0}),setTimeout(t,2e3);break;case"ERROR":e.setState({isLoading:!1,errorMsg:(0,f.ih)("Document convertion failed.")});break;case"DONE":e.setState({isLoading:!1,errorMsg:""});var r=document.createElement("script");r.type="text/javascript",r.src="".concat(f.si,"js/pdf/web/viewer.js"),document.body.append(r)}})).catch((function(t){t.response?e.setState({isLoading:!1,errorMsg:(0,f.ih)("Document convertion failed.")}):e.setState({isLoading:!1,errorMsg:(0,f.ih)("Please check the network.")})}))}()}}},{key:"render",value:function(){var e=this.state,t=e.isLoading,n=e.errorMsg;return w?(0,v.jsx)(p.Z,{}):t?(0,v.jsx)(h.Z,{}):n?(0,v.jsx)(p.Z,{errorMsg:n}):(0,v.jsx)("div",{className:"file-view-content flex-1 pdf-file-view",children:(0,v.jsx)(l.Z,{})})}}]),n}(a.Component);c.render((0,v.jsx)(x,{}),document.getElementById("wrapper"))}},function(e){e.O(0,[351],(function(){return t=80015,e(e.s=t);var t}));e.O()}]);