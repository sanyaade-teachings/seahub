"use strict";(self.webpackChunkseahub_frontend=self.webpackChunkseahub_frontend||[]).push([[798],{9820:function(e,n,t){var r=t(15671),a=t(43144),i=t(60136),o=t(29388),s=t(47313),u=t(1168),d=t(14165),c=t(4514),f=t(83854),h=t(61805),l=t(37434),g=t(52340),v=t(51282),m=t(68396),x=t(46417),p=window.shared.pageOptions,w=p.repoID,k=p.sharedToken,Z=p.rawPath,b=p.err,j=function(e){(0,i.Z)(t,e);var n=(0,o.Z)(t);function t(){return(0,r.Z)(this,t),n.apply(this,arguments)}return(0,a.Z)(t,[{key:"render",value:function(){return(0,x.jsx)(l.Z,{content:(0,x.jsx)(y,{}),fileType:"md"})}}]),t}(s.Component),y=function(e){(0,i.Z)(t,e);var n=(0,o.Z)(t);function t(e){var a;return(0,r.Z)(this,t),(a=n.call(this,e)).changeImageURL=function(e){if("image"==e.type){var n=e.data.src;if(!new RegExp(h.xx+"/lib/"+w+"/file.*raw=1").test(n))return;var t=n.substring(h.xx.length),r=t.indexOf("/file"),a=t.indexOf("?");t=t.substring(r+5,a),e.data.src=h.xx+"/view-image-via-share-link/?token="+k+"&path="+t}return e},a.modifyValueBeforeRender=function(e){return f.c.changeMarkdownNodes(e,a.changeImageURL)},a.state={markdownContent:"",loading:!b},a}return(0,a.Z)(t,[{key:"componentDidMount",value:function(){var e=this;c.I.getFileContent(Z).then((function(n){e.setState({markdownContent:n.data,loading:!1})})).catch((function(e){var n=f.c.getErrorMsg(e);m.Z.danger(n)}))}},{key:"render",value:function(){return b?(0,x.jsx)(g.Z,{}):this.state.loading?(0,x.jsx)(v.Z,{}):(0,x.jsx)("div",{className:"shared-file-view-body md-view",children:(0,x.jsx)(d.av,{value:this.state.markdownContent,isShowOutline:!0,mathJaxSource:h.si+"js/mathjax/tex-svg.js",beforeRenderCallback:this.modifyValueBeforeRender})})}}]),t}(s.Component);u.render((0,x.jsx)(j,{}),document.getElementById("wrapper"))}},function(e){e.O(0,[351],(function(){return n=9820,e(e.s=n);var n}));e.O()}]);