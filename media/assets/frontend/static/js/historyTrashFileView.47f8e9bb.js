"use strict";(self.webpackChunkseahub_frontend=self.webpackChunkseahub_frontend||[]).push([[315],{43906:function(e,n,t){var a=t(1413),i=t(15671),r=t(43144),o=t(60136),c=t(29388),s=t(47313),l=t(84760),u=(t(69155),t(46417)),p=window.app.pageOptions.rawPath,f=function(e){(0,o.Z)(t,e);var n=(0,c.Z)(t);function t(){return(0,i.Z)(this,t),n.apply(this,arguments)}return(0,r.Z)(t,[{key:"render",value:function(){var e={autoplay:!1,controls:!0,preload:"auto",sources:[{src:p}]};return(0,u.jsx)("div",{className:"file-view-content flex-1 audio-file-view",children:(0,u.jsx)(l.Z,(0,a.Z)({},e))})}}]),t}(s.Component);n.Z=f},92451:function(e,n,t){var a,i,r=t(15671),o=t(43144),c=t(60136),s=t(29388),l=t(47313),u=t(83854),p=t(61805),f=(t(61846),t(46417)),d=window.app.pageOptions,h=d.repoID,v=d.repoEncrypted,x=d.fileExt,m=d.filePath,w=d.fileName,Z=d.thumbnailSizeForOriginal,j=d.previousImage,k=d.nextImage,y=d.rawPath,g=d.xmindImageSrc;j&&(a="".concat(p.ze,"lib/").concat(h,"/file").concat(u.c.encodePath(j))),k&&(i="".concat(p.ze,"lib/").concat(h,"/file").concat(u.c.encodePath(k)));var N=function(e){(0,c.Z)(t,e);var n=(0,s.Z)(t);function t(e){var a;return(0,r.Z)(this,t),(a=n.call(this,e)).handleLoadFailure=function(){a.setState({loadFailed:!0})},a.state={loadFailed:!1},a}return(0,o.Z)(t,[{key:"componentDidMount",value:function(){document.addEventListener("keydown",(function(e){j&&37==e.keyCode&&(location.href=a),k&&39==e.keyCode&&(location.href=i)}))}},{key:"render",value:function(){if(this.state.loadFailed)return this.props.tip;var e="";!v&&["tif","tiff","psd"].includes(x)&&(e="".concat(p.ze,"thumbnail/").concat(h,"/").concat(Z).concat(u.c.encodePath(m)));var n=g?"".concat(p.ze).concat(g):"";return(0,f.jsxs)("div",{className:"file-view-content flex-1 image-file-view",children:[j&&(0,f.jsx)("a",{href:a,id:"img-prev",title:(0,p.ih)("you can also press \u2190 "),children:(0,f.jsx)("span",{className:"fas fa-chevron-left"})}),k&&(0,f.jsx)("a",{href:i,id:"img-next",title:(0,p.ih)("you can also press \u2192"),children:(0,f.jsx)("span",{className:"fas fa-chevron-right"})}),(0,f.jsx)("img",{src:n||e||y,alt:w,id:"image-view",onError:this.handleLoadFailure})]})}}]),t}(l.Component);n.Z=N},18652:function(e,n,t){var a=t(15671),i=t(43144),r=t(60136),o=t(29388),c=t(47313),s=t(17008),l=(t(88892),t(46417)),u=function(e){(0,r.Z)(t,e);var n=(0,o.Z)(t);function t(){return(0,a.Z)(this,t),n.apply(this,arguments)}return(0,i.Z)(t,[{key:"render",value:function(){return(0,l.jsx)("div",{className:"file-view-content flex-1 pdf-file-view",children:(0,l.jsx)(s.Z,{})})}}]),t}(c.Component);n.Z=u},14699:function(e,n,t){var a=t(15671),i=t(43144),r=t(60136),o=t(29388),c=t(47313),s=(t(2644),t(46417)),l=window.app.pageOptions,u=l.fileName,p=l.rawPath,f=function(e){(0,r.Z)(t,e);var n=(0,o.Z)(t);function t(){return(0,a.Z)(this,t),n.apply(this,arguments)}return(0,i.Z)(t,[{key:"render",value:function(){return(0,s.jsx)("div",{className:"file-view-content flex-1 svg-file-view",children:(0,s.jsx)("img",{src:p,alt:u,id:"svg-view"})})}}]),t}(c.Component);n.Z=f},66075:function(e,n,t){var a=t(1413),i=t(15671),r=t(43144),o=t(60136),c=t(29388),s=t(47313),l=t(97128),u=(t(65360),t(46417)),p=window.app.pageOptions.rawPath,f=function(e){(0,o.Z)(t,e);var n=(0,c.Z)(t);function t(){return(0,i.Z)(this,t),n.apply(this,arguments)}return(0,r.Z)(t,[{key:"render",value:function(){var e={autoplay:!1,controls:!0,preload:"auto",playbackRates:[.5,1,1.5,2],sources:[{src:p}]};return(0,u.jsx)("div",{className:"file-view-content flex-1 video-file-view",children:(0,u.jsx)(l.Z,(0,a.Z)({},e))})}}]),t}(s.Component);n.Z=f},84106:function(e,n,t){var a=t(15671),i=t(43144),r=t(60136),o=t(29388),c=t(47313),s=t(1168),l=t(31929),u=t.n(l),p=t(61805),f=t(46417),d=window.app.pageOptions,h=d.fileName,v=d.repoID,x=d.objID,m=d.path;var w=function(){return(0,f.jsx)("a",{href:"".concat(p.ze,"repo/").concat(v,"/").concat(x,"/download/?file_name=").concat(encodeURIComponent(h),"&p=").concat(encodeURIComponent(m)),className:"btn btn-secondary flex-shrink-0",children:(0,p.ih)("Download")})},Z=(t(98258),window.app.pageOptions),j=Z.fromTrash,k=Z.fileName,y=Z.commitTime,g=Z.canDownloadFile,N=Z.enableWatermark,b=Z.userNickName,C=function(e){(0,r.Z)(t,e);var n=(0,o.Z)(t);function t(e){return(0,a.Z)(this,t),n.call(this,e)}return(0,i.Z)(t,[{key:"render",value:function(){return(0,f.jsxs)("div",{className:"h-100 d-flex flex-column flex-1 mw-100",children:[(0,f.jsxs)("div",{className:"file-view-header d-flex justify-content-between align-items-center",children:[(0,f.jsxs)("div",{className:"text-truncate mr-4",children:[(0,f.jsx)("h2",{className:"file-title text-truncate",title:k,children:k}),(0,f.jsx)("p",{className:"meta-info m-0",children:j?"".concat((0,p.ih)("Current Path: ")).concat((0,p.ih)("Trash")):y})]}),g&&(0,f.jsx)(w,{})]}),(0,f.jsx)("div",{className:"file-view-body flex-auto d-flex o-hidden",children:this.props.content})]})}}]),t}(c.Component);N&&u().init({watermark_txt:"".concat(p.aD," ").concat(b),watermark_alpha:.075});var O=C,F=window.app.pageOptions,D=F.canDownloadFile,I=F.err,P="File preview unsupported",S=function(e){(0,r.Z)(t,e);var n=(0,o.Z)(t);function t(){return(0,a.Z)(this,t),n.apply(this,arguments)}return(0,i.Z)(t,[{key:"render",value:function(){var e;return e=I==P||this.props.err==P?(0,f.jsx)("p",{children:(0,p.ih)("Online view is not applicable to this file format")}):(0,f.jsx)("p",{className:"error",children:I}),(0,f.jsx)("div",{className:"file-view-content flex-1 o-auto",children:(0,f.jsxs)("div",{className:"file-view-tip",children:[e,D&&(0,f.jsx)(w,{})]})})}}]),t}(c.Component),E=S,z=t(92451),T=t(14699),_=t(18652),L=t(90930),M=(t(85387),window.app.pageOptions),R=M.fileExt,V=M.fileContent,J=function(e){(0,r.Z)(t,e);var n=(0,o.Z)(t);function t(){return(0,a.Z)(this,t),n.apply(this,arguments)}return(0,i.Z)(t,[{key:"render",value:function(){return(0,f.jsx)("div",{className:"file-view-content flex-1 text-file-view",children:(0,f.jsx)(L.Z,{fileExt:R,value:V})})}}]),t}(c.Component),U=J,A=t(95423),B=window.app.pageOptions.fileContent,G=function(e){(0,r.Z)(t,e);var n=(0,o.Z)(t);function t(){return(0,a.Z)(this,t),n.apply(this,arguments)}return(0,i.Z)(t,[{key:"render",value:function(){return(0,f.jsx)("div",{className:"file-view-content md-content",children:(0,f.jsx)(A.MarkdownViewer,{isFetching:!1,value:B,isShowOutline:!1,mathJaxSource:p.si+"js/mathjax/tex-svg.js"})})}}]),t}(c.Component),W=G,q=t(88529),H=window.app.pageOptions.fileContent,K=function(e){(0,r.Z)(t,e);var n=(0,o.Z)(t);function t(){return(0,a.Z)(this,t),n.apply(this,arguments)}return(0,i.Z)(t,[{key:"render",value:function(){var e=H?JSON.parse(H):null;return(0,f.jsx)("div",{className:"file-view-content flex-1 o-auto sdoc-file-view p-0 d-flex flex-column",children:(0,f.jsx)(q.ZO,{document:e})})}}]),t}(c.Component),Q=K,X=t(66075),Y=t(43906),$=window.app.pageOptions,ee=$.fileType,ne=$.err,te=function(e){(0,r.Z)(t,e);var n=(0,o.Z)(t);function t(){return(0,a.Z)(this,t),n.apply(this,arguments)}return(0,i.Z)(t,[{key:"render",value:function(){if(ne)return(0,f.jsx)(O,{content:(0,f.jsx)(E,{})});var e;switch(ee){case"Image":e=(0,f.jsx)(z.Z,{tip:(0,f.jsx)(E,{})});break;case"SVG":e=(0,f.jsx)(T.Z,{});break;case"PDF":e=(0,f.jsx)(_.Z,{});break;case"Text":e=(0,f.jsx)(U,{});break;case"Markdown":e=(0,f.jsx)(W,{});break;case"SDoc":e=(0,f.jsx)(Q,{});break;case"Video":e=(0,f.jsx)(X.Z,{});break;case"Audio":e=(0,f.jsx)(Y.Z,{});break;default:e=(0,f.jsx)(E,{err:"File preview unsupported"})}return(0,f.jsx)(O,{content:e})}}]),t}(c.Component);s.render((0,f.jsx)(te,{}),document.getElementById("wrapper"))}},function(e){e.O(0,[351],(function(){return n=84106,e(e.s=n);var n}));e.O()}]);