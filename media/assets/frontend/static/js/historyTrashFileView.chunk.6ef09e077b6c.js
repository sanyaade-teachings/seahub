(this["webpackJsonpseahub-frontend"]=this["webpackJsonpseahub-frontend"]||[]).push([[9],{1574:function(e,t,a){a(55),e.exports=a(1703)},1575:function(e,t,a){},1703:function(e,t,a){"use strict";a.r(t);var n=a(6),c=a(7),i=a(9),r=a(8),o=a(2),s=a.n(o),l=a(24),j=a.n(l),u=a(258),p=a.n(u),b=a(1),d=a(0),f=window.app.pageOptions,O=f.fileName,h=f.repoID,v=f.objID,m=f.path;var x=function(){return Object(d.jsx)("a",{href:"".concat(b.qc,"repo/").concat(h,"/").concat(v,"/download/?file_name=").concat(encodeURIComponent(O),"&p=").concat(encodeURIComponent(m)),className:"btn btn-secondary",children:Object(b.qb)("Download")})},w=(a(768),window.app.pageOptions),y=w.fromTrash,g=w.fileName,k=w.commitTime,N=w.canDownloadFile,C=w.enableWatermark,q=w.userNickName,F=function(e){Object(i.a)(a,e);var t=Object(r.a)(a);function a(e){return Object(n.a)(this,a),t.call(this,e)}return Object(c.a)(a,[{key:"render",value:function(){return Object(d.jsxs)("div",{className:"h-100 d-flex flex-column",children:[Object(d.jsxs)("div",{className:"file-view-header d-flex justify-content-between align-items-center",children:[Object(d.jsxs)("div",{children:[Object(d.jsx)("h2",{className:"file-title",children:g}),Object(d.jsx)("p",{className:"meta-info m-0",children:y?"".concat(Object(b.qb)("Current Path: ")).concat(Object(b.qb)("Trash")):k})]}),N&&Object(d.jsx)(x,{})]}),Object(d.jsx)("div",{className:"file-view-body flex-auto d-flex o-hidden",children:this.props.content})]})}}]),a}(s.a.Component);C&&p.a.init({watermark_txt:"".concat(b.pc," ").concat(q),watermark_alpha:.075});var I=F,P=window.app.pageOptions,D=P.canDownloadFile,E=P.err,T="File preview unsupported",S=function(e){Object(i.a)(a,e);var t=Object(r.a)(a);function a(){return Object(n.a)(this,a),t.apply(this,arguments)}return Object(c.a)(a,[{key:"render",value:function(){var e;return e=E==T||this.props.err==T?Object(d.jsx)("p",{children:Object(b.qb)("Online view is not applicable to this file format")}):Object(d.jsx)("p",{className:"error",children:E}),Object(d.jsx)("div",{className:"file-view-content flex-1 o-auto",children:Object(d.jsxs)("div",{className:"file-view-tip",children:[e,D&&Object(d.jsx)(x,{})]})})}}]),a}(s.a.Component),L=a(262),R=a(324),W=a(325),_=a(5),B=a(259),J=a.n(B),M=(a(243),a(213),a(370),a(510),a(511),a(512),a(205),a(513),a(514),a(310),a(293),a(515),window.app.pageOptions),U=M.fileExt,V=M.fileContent,z={lineNumbers:!0,mode:_.a.chooseLanguage(U),extraKeys:{Ctrl:"autocomplete"},theme:"default",textWrapping:!0,lineWrapping:!0,readOnly:!0,cursorBlinkRate:-1},A=function(e){Object(i.a)(a,e);var t=Object(r.a)(a);function a(){return Object(n.a)(this,a),t.apply(this,arguments)}return Object(c.a)(a,[{key:"render",value:function(){return Object(d.jsx)("div",{className:"file-view-content flex-1 text-file-view",children:Object(d.jsx)(J.a,{ref:"code-mirror-editor",value:V,options:z})})}}]),a}(s.a.Component),G=a(110),K=(a(1575),window.app.pageOptions.fileContent),H=function(e){Object(i.a)(a,e);var t=Object(r.a)(a);function a(){return Object(n.a)(this,a),t.apply(this,arguments)}return Object(c.a)(a,[{key:"render",value:function(){return Object(d.jsx)("div",{className:"file-view-content flex-1 o-auto",children:Object(d.jsx)("div",{className:"md-content",children:Object(d.jsx)(G.a,{markdownContent:K,showTOC:!1,scriptSource:b.Ob+"js/mathjax/tex-svg.js"})})})}}]),a}(s.a.Component),Q=a(326),X=a(327),Y=window.app.pageOptions,Z=Y.fileType,$=Y.err,ee=function(e){Object(i.a)(a,e);var t=Object(r.a)(a);function a(){return Object(n.a)(this,a),t.apply(this,arguments)}return Object(c.a)(a,[{key:"render",value:function(){if($)return Object(d.jsx)(I,{content:Object(d.jsx)(S,{})});var e;switch(Z){case"Image":e=Object(d.jsx)(L.a,{tip:Object(d.jsx)(S,{})});break;case"SVG":e=Object(d.jsx)(R.a,{});break;case"PDF":e=Object(d.jsx)(W.a,{});break;case"Text":e=Object(d.jsx)(A,{});break;case"Markdown":e=Object(d.jsx)(H,{});break;case"Video":e=Object(d.jsx)(Q.a,{});break;case"Audio":e=Object(d.jsx)(X.a,{});break;default:e=Object(d.jsx)(S,{err:"File preview unsupported"})}return Object(d.jsx)(I,{content:e})}}]),a}(s.a.Component);j.a.render(Object(d.jsx)(ee,{}),document.getElementById("wrapper"))},262:function(e,t,a){"use strict";var n,c,i=a(6),r=a(7),o=a(9),s=a(8),l=a(2),j=a.n(l),u=a(5),p=a(1),b=(a(516),a(0)),d=window.app.pageOptions,f=d.repoID,O=d.repoEncrypted,h=d.fileExt,v=d.filePath,m=d.fileName,x=d.thumbnailSizeForOriginal,w=d.previousImage,y=d.nextImage,g=d.rawPath,k=d.xmindImageSrc;w&&(n="".concat(p.qc,"lib/").concat(f,"/file").concat(u.a.encodePath(w))),y&&(c="".concat(p.qc,"lib/").concat(f,"/file").concat(u.a.encodePath(y)));var N=function(e){Object(o.a)(a,e);var t=Object(s.a)(a);function a(e){var n;return Object(i.a)(this,a),(n=t.call(this,e)).handleLoadFailure=function(){n.setState({loadFailed:!0})},n.state={loadFailed:!1},n}return Object(r.a)(a,[{key:"componentDidMount",value:function(){document.addEventListener("keydown",(function(e){w&&37==e.keyCode&&(location.href=n),y&&39==e.keyCode&&(location.href=c)}))}},{key:"render",value:function(){if(this.state.loadFailed)return this.props.tip;var e="";!O&&["tif","tiff","psd"].includes(h)&&(e="".concat(p.qc,"thumbnail/").concat(f,"/").concat(x).concat(u.a.encodePath(v)));var t=k?"".concat(p.qc).concat(k):"";return Object(b.jsxs)("div",{className:"file-view-content flex-1 image-file-view",children:[w&&Object(b.jsx)("a",{href:n,id:"img-prev",title:Object(p.qb)("you can also press \u2190 "),children:Object(b.jsx)("span",{className:"fas fa-chevron-left"})}),y&&Object(b.jsx)("a",{href:c,id:"img-next",title:Object(p.qb)("you can also press \u2192"),children:Object(b.jsx)("span",{className:"fas fa-chevron-right"})}),Object(b.jsx)("img",{src:t||e||g,alt:m,id:"image-view",onError:this.handleLoadFailure})]})}}]),a}(j.a.Component);t.a=N},324:function(e,t,a){"use strict";var n=a(6),c=a(7),i=a(9),r=a(8),o=a(2),s=a.n(o),l=(a(519),a(0)),j=window.app.pageOptions,u=j.fileName,p=j.rawPath,b=function(e){Object(i.a)(a,e);var t=Object(r.a)(a);function a(){return Object(n.a)(this,a),t.apply(this,arguments)}return Object(c.a)(a,[{key:"render",value:function(){return Object(l.jsx)("div",{className:"file-view-content flex-1 svg-file-view",children:Object(l.jsx)("img",{src:p,alt:u,id:"svg-view"})})}}]),a}(s.a.Component);t.a=b},325:function(e,t,a){"use strict";var n=a(6),c=a(7),i=a(9),r=a(8),o=a(2),s=a.n(o),l=a(160),j=(a(311),a(0)),u=function(e){Object(i.a)(a,e);var t=Object(r.a)(a);function a(){return Object(n.a)(this,a),t.apply(this,arguments)}return Object(c.a)(a,[{key:"render",value:function(){return Object(j.jsx)("div",{className:"file-view-content flex-1 pdf-file-view",children:Object(j.jsx)(l.a,{})})}}]),a}(s.a.Component);t.a=u},326:function(e,t,a){"use strict";var n=a(37),c=a(6),i=a(7),r=a(9),o=a(8),s=a(2),l=a.n(s),j=a(260),u=(a(518),a(0)),p=window.app.pageOptions.rawPath,b=function(e){Object(r.a)(a,e);var t=Object(o.a)(a);function a(){return Object(c.a)(this,a),t.apply(this,arguments)}return Object(i.a)(a,[{key:"render",value:function(){var e={autoplay:!1,controls:!0,preload:"auto",sources:[{src:p}]};return Object(u.jsx)("div",{className:"file-view-content flex-1 video-file-view",children:Object(u.jsx)(j.a,Object(n.a)({},e))})}}]),a}(l.a.Component);t.a=b},327:function(e,t,a){"use strict";var n=a(37),c=a(6),i=a(7),r=a(9),o=a(8),s=a(2),l=a.n(s),j=a(261),u=(a(520),a(0)),p=window.app.pageOptions.rawPath,b=function(e){Object(r.a)(a,e);var t=Object(o.a)(a);function a(){return Object(c.a)(this,a),t.apply(this,arguments)}return Object(i.a)(a,[{key:"render",value:function(){var e={autoplay:!1,controls:!0,preload:"auto",sources:[{src:p}]};return Object(u.jsx)("div",{className:"file-view-content flex-1 audio-file-view",children:Object(u.jsx)(j.a,Object(n.a)({},e))})}}]),a}(l.a.Component);t.a=b}},[[1574,1,0]]]);
//# sourceMappingURL=historyTrashFileView.chunk.js.map