(this["webpackJsonpseahub-frontend"]=this["webpackJsonpseahub-frontend"]||[]).push([[21],{1713:function(e,t,n){n(75),e.exports=n(1714)},1714:function(e,t,n){"use strict";n.r(t);var a=n(3),r=n(5),s=n(7),c=n(6),o=n(2),i=n.n(o),u=n(31),b=n.n(u),d=n(8),j=n(1),f=n(105),p=n(94),O=n(19),h=n(182),l=(n(347),n(0)),v=window.shared.pageOptions,g=v.repoID,m=v.filePath,w=v.err,k=v.commitID,x=v.fileType,y=v.sharedToken,L=function(e){Object(s.a)(n,e);var t=Object(c.a)(n);function n(){return Object(a.a)(this,n),t.apply(this,arguments)}return Object(r.a)(n,[{key:"render",value:function(){return Object(l.jsx)(f.a,{content:Object(l.jsx)(M,{})})}}]),n}(i.a.Component),M=function(e){Object(s.a)(n,e);var t=Object(c.a)(n);function n(e){var r;return Object(a.a)(this,n),(r=t.call(this,e)).state={isLoading:!w,errorMsg:""},r}return Object(r.a)(n,[{key:"componentDidMount",value:function(){var e=this;if(!w){!function t(){d.a.queryOfficeFileConvertStatus(g,k,m,x.toLowerCase(),y).then((function(n){switch(n.data.status){case"PROCESSING":e.setState({isLoading:!0}),setTimeout(t,2e3);break;case"ERROR":e.setState({isLoading:!1,errorMsg:Object(j.sb)("Document convertion failed.")});break;case"DONE":e.setState({isLoading:!1,errorMsg:""});var a=document.createElement("script");a.type="text/javascript",a.src="".concat(j.Qb,"js/pdf/web/viewer.js"),document.body.append(a)}})).catch((function(t){t.response?e.setState({isLoading:!1,errorMsg:Object(j.sb)("Document convertion failed.")}):e.setState({isLoading:!1,errorMsg:Object(j.sb)("Please check the network.")})}))}()}}},{key:"render",value:function(){var e=this.state,t=e.isLoading,n=e.errorMsg;return w?Object(l.jsx)(p.a,{}):t?Object(l.jsx)(O.a,{}):n?Object(l.jsx)(p.a,{errorMsg:n}):Object(l.jsx)("div",{className:"shared-file-view-body pdf-file-view",children:Object(l.jsx)(h.a,{})})}}]),n}(i.a.Component);b.a.render(Object(l.jsx)(L,{}),document.getElementById("wrapper"))}},[[1713,1,0]]]);
//# sourceMappingURL=sharedFileViewDocument.chunk.js.map