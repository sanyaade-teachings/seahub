(this["webpackJsonpseahub-frontend"]=this["webpackJsonpseahub-frontend"]||[]).push([[35],{1724:function(t,e,n){n(76),t.exports=n(1725)},1725:function(t,e,n){"use strict";n.r(e);var a=n(32),i=n(3),s=n(5),c=n(7),r=n(6),o=n(2),p=n.n(o),u=n(31),d=n.n(u),h=n(10),v=n(1),f=n(204),l=n(297),b=n(164),j=n(8),S=(n(545),n(0)),O=window.app.pageOptions,g=O.err,P=O.fileExt,x=O.fileContent,C=O.repoID,m=O.filePath,y=O.fileName,k=O.canEditFile,w=O.username,E=function(t){Object(c.a)(n,t);var e=Object(r.a)(n);function n(){return Object(i.a)(this,n),e.apply(this,arguments)}return Object(s.a)(n,[{key:"render",value:function(){return g?Object(S.jsx)(b.a,{}):Object(S.jsx)("div",{className:"file-view-content flex-1 text-file-view",children:Object(S.jsx)(l.a,{fileExt:P,value:this.props.content,readOnly:!k,onChange:this.props.updateContent})})}}]),n}(p.a.Component),F=function(t){Object(c.a)(n,t);var e=Object(r.a)(n);function n(t){var s;return Object(i.a)(this,n),(s=e.call(this,t)).updateContent=function(t){s.setState({needSave:!0,content:t})},s.addParticipant=function(){j.a.addFileParticipants(C,m,[w]).then((function(t){200===t.status&&(s.isParticipant=!0,s.getParticipants())}))},s.getParticipants=function(){j.a.listFileParticipants(C,m).then((function(t){var e=t.data.participant_list;s.setState({participants:e}),e.length>0&&(s.isParticipant=e.every((function(t){return t.email==w})))}))},s.onParticipantsChange=function(){s.getParticipants()},s.state={content:x,needSave:!1,isSaving:!1,participants:[]},s.onSave=s.onSave.bind(Object(a.a)(s)),s.isParticipant=!1,s}return Object(s.a)(n,[{key:"onSave",value:function(){var t=this;this.isParticipant||this.addParticipant();return j.a.getUpdateLink(C,"/").then((function(e){var n=e.data;return t.setState({isSaving:!0}),j.a.updateFile(n,m,y,t.state.content).then((function(){h.a.success(Object(v.tb)("Successfully saved"),{duration:2}),t.setState({isSaving:!1,needSave:!1})}))}))}},{key:"componentDidMount",value:function(){this.getParticipants()}},{key:"render",value:function(){return Object(S.jsx)(f.a,{content:Object(S.jsx)(E,{content:this.state.content,updateContent:this.updateContent}),isSaving:this.state.isSaving,needSave:this.state.needSave,onSave:this.onSave,participants:this.state.participants,onParticipantsChange:this.onParticipantsChange})}}]),n}(p.a.Component);d.a.render(Object(S.jsx)(F,{}),document.getElementById("wrapper"))}},[[1724,1,0]]]);
//# sourceMappingURL=viewFileText.chunk.js.map