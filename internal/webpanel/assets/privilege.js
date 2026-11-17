"use strict";

const privilegeRuleLabels = {
  "privilege-root-execution": {title:"전역 root 실행 관측",description:"EUID 0 실행과 주변 문맥을 관측했습니다. 승인된 작업인지 확인하세요."},
  "privilege-root-restored": {title:"기존 root 자격으로 실행 권한 복귀",description:"같은 user namespace에서 UID 또는 saved UID 0을 가진 작업이 EUID 0으로 복귀했습니다. 인증·인가가 확인됐다는 뜻은 아닙니다."},
  "privilege-host-root-gain": {title:"초기 user namespace의 root 권한 변경",description:"같은 초기 user namespace에서 EUID 비0→0 적용을 관측했습니다. 승인된 권한 상승인지 확인하세요. 컨테이너 탈출을 확정하지 않습니다."},
  "privilege-root-identity-change": {title:"root 실행 신원 변경 관측",description:"EUID 비0→0 적용을 관측했습니다. namespace가 다르거나 확인되지 않을 수 있으므로 호스트 권한 탈취로 단정하지 않습니다."},
  "privilege-capability-gain": {title:"프로세스 Capability 권한집합 증가",description:"보유 권한집합이 늘어난 것을 관측했습니다. user namespace와 승인된 작업 범위를 확인하세요."},
  "privilege-capability-activated": {title:"기존 Capability의 실행 권한 활성화",description:"이미 permitted에 있던 권한이 effective로 활성화됐습니다. 새 permitted 권한 획득과 구분해 확인하세요."},
};
const privilegeFactorLabels = {
  root_execution:"EUID 0 실행을 관측했습니다. 권한 상승 원인을 확정하지 않습니다.",
  nonroot_parent_snapshot:"상위 프로세스의 실행 스냅샷에 EUID 비0이 있었습니다. 부모의 현재 권한이나 공격 성공을 증명하지 않습니다.",
  privileged_exec_metadata:"SUID·SGID·파일 Capability 관련 실행 메타데이터를 관측했습니다.",
  unattributed_shell:"서비스 출처를 확인하지 못한 root 셸 실행을 관측했습니다.",
  root_identity_restored:"같은 user namespace에서 보유한 UID/SUID 0 자격으로 EUID가 복귀했습니다. 승인된 작업인지 확인이 필요합니다.",
  initial_namespace_root_gain:"같은 초기 user namespace에서 EUID 비0→0 변경 적용을 관측했습니다.",
  root_identity_change:"EUID 비0→0 변경 적용을 관측했습니다. namespace 범위를 별도로 확인해야 합니다.",
  additional_capability_gain:"root 신원 변경과 함께 새 Capability 권한집합 증가가 관측됐습니다.",
  capability_gain:"이전 snapshot보다 permitted 또는 새 effective 권한이 늘었습니다.",
  permitted_capability_activation:"이전 permitted 범위 안의 권한이 effective로 활성화됐습니다.",
  sensitive_capability_gain:"민감한 Capability가 새로 관측됐습니다. 실제 권한 범위는 user namespace에 따라 다릅니다.",
};
function isPrivilegeRule(value) {return Object.hasOwn(privilegeRuleLabels,value);}
function findingResponseLabel(finding) {return finding?.detection_only===true&&isPrivilegeRule(finding.rule_id)?"권한 탐지 전용":operatorLabel("response",finding?.detection_only===true?"detection_only":finding?.response_decision||"unknown");}
function privilegeConfidence(value) {
  return Number.isFinite(value)?`관측 근거 지표 · 원본 값 ${value} · 악성 확률이나 인증·인가 확인을 뜻하지 않습니다.`:"관측 근거 지표 미확인";
}
function privilegeProfileNote(summary) {
  if(!summary?.privilege_rules)return "";
  const mode=summary.root_exec_alerts==="all"?"모든 root 실행 경보":"의심 문맥의 root 실행 경보";
  return `전역 root 실행 관측·${mode} 및 권한 변경 규칙은 탐지 전용입니다. 기존 웹 규칙의 대응 설정과 구분됩니다.`;
}
function privilegeObject(value){return value&&typeof value==="object"&&!Array.isArray(value)?value:{};}
function privilegeAvailable(event,path){
  for(const [group,fields] of [event.missing_fields,event.redacted_fields,event.truncated_fields].entries())for(const missing of Array.isArray(fields)?fields:[]){
    // Scope uncertainty is separate from loss of same-hook paired evidence.
    if(group===0&&path==="credential"&&missing==="credential.user_namespace_scope"){
      const credential=privilegeObject(event.credential);
      if([credential.before,credential.after].some(snapshot=>typeof privilegeObject(privilegeObject(snapshot).user_namespace).is_host!=="boolean"))continue;
    }
    if(typeof missing==="string"&&(missing===path||path.startsWith(`${missing}.`)||missing.startsWith(`${path}.`)||missing.startsWith(`${path}[`)))return false;
  }
  return true;
}
function privilegeID(value){return Number.isInteger(value)&&value>=0&&value<4294967295?String(value):"미수집";}
function privilegeTaskID(value){return Number.isSafeInteger(value)&&value>0?String(value):"미확인";}
// The wire contract uses decimal text so uint64 task identity survives JSON
// without JavaScript's integer rounding. Legacy numeric values are unknown.
function privilegeTaskStart(value) {
  if(typeof value!=="string"||!/^[1-9][0-9]{0,19}$/.test(value))return "미확인";
  return value.length<20||value<="18446744073709551615"?value:"미확인";
}
function privilegeNamespaceValid(value) {
  const ns=privilegeObject(value);
  return Number.isInteger(ns.inum)&&ns.inum>0&&ns.inum<=4294967295&&
    (ns.is_host===undefined||typeof ns.is_host==="boolean")&&
    (ns.level===undefined||(Number.isInteger(ns.level)&&ns.level>=0&&ns.level<=64&&
      (ns.is_host===undefined||((ns.level===0)===ns.is_host))));
}
function privilegeNamespace(value){
  const ns=privilegeObject(value),known=privilegeNamespaceValid(ns);
  if(!known||typeof ns.is_host!=="boolean")return "미확인";
  return `${ns.is_host?"초기 user namespace":"비호스트 user namespace"} · inode ${ns.inum}`;
}
function privilegeCapabilitySet(value){
  if(!Array.isArray(value)||value.length>64||value.some(name=>typeof name!=="string"||!/^CAP_[A-Z0-9_]{1,63}$/.test(name))||new Set(value).size!==value.length)return null;
  return [...value].sort();
}
function privilegeCapabilitiesText(value){const set=privilegeCapabilitySet(value);return set===null?"미수집":set.length?set.join(" · "):"없음 (확인됨)";}
function privilegeSnapshotComplete(snapshot){
 const value=privilegeObject(snapshot),caps=privilegeObject(value.capabilities),ns=privilegeObject(value.user_namespace);
 return ["uid","euid","gid","egid","suid","sgid","fsuid","fsgid"].every(key=>privilegeID(value[key])!=="미수집")&&
  ["effective","permitted","inheritable"].every(key=>privilegeCapabilitySet(caps[key])!==null)&&privilegeNamespaceValid(ns);
}
function privilegeCredentialObservation(event){
 const value=privilegeObject(event.credential),before=privilegeObject(value.before),after=privilegeObject(value.after),process=privilegeObject(event.process);
 const identity=Number.isSafeInteger(value.tid)&&value.tid>0&&value.tid<=2147483647&&Number.isSafeInteger(value.tgid)&&value.tgid>0&&value.tgid<=2147483647&&value.tgid===process.pid&&(!process.tid||process.tid===value.tid)&&privilegeTaskStart(value.task_start_time_ns)!=="미확인";
 const fixed=value.evidence==="tetragon_commit_creds_pair"&&value.policy_name==="xeas-credential-change-v1"&&value.function==="commit_creds";
 const sourceIdentity=typeof event.boot_id==="string"&&event.boot_id!==""&&typeof process.exec_id==="string"&&process.exec_id!==""&&typeof process.start_time==="string"&&!process.start_time.startsWith("0001-01-01")&&Number.isFinite(Date.parse(process.start_time))&&typeof event.event_time==="string"&&!event.event_time.startsWith("0001-01-01")&&Number.isFinite(Date.parse(event.event_time));
 const paired=event.source==="tetragon"&&fixed&&identity&&sourceIdentity&&["credential","process.pid","process.tid","process.exec_id","process.start_time","event_time","boot_id"].every(path=>privilegeAvailable(event,path))&&privilegeSnapshotComplete(before)&&privilegeSnapshotComplete(after);
 const applied=paired&&value.return_value===0&&value.outcome==="applied";
 let summary=applied?"같은 커널 호출에서 이전·이후 자격 증명과 적용 반환을 관측했습니다. 승인된 작업인지는 별도로 확인해야 합니다.":"자격 증명 변경 관측의 일부 근거 또는 적용 결과를 확인할 수 없습니다. 정확한 이전→이후 변경으로 단정하지 않습니다.";
 if(value.outcome==="failed"&&Number.isSafeInteger(value.return_value)&&value.return_value<0)summary="자격 증명 변경 호출이 실패로 보고됐습니다. root 권한 획득을 뜻하지 않습니다.";
 const id=(snapshot,key,path)=>privilegeAvailable(event,path)?privilegeID(snapshot[key]):"미수집";
 const cap=(snapshot,key,path)=>privilegeAvailable(event,path)?privilegeCapabilitiesText(privilegeObject(snapshot.capabilities)[key]):"미수집";
 const fields=[
  ["적용 결과",applied?"변경 적용 근거 확인":value.outcome==="failed"?"실패 보고":"적용 근거 미확인"],
  ["이전 실제 사용자 UID",id(before,"uid","credential.before.uid")],["이후 실제 사용자 UID",id(after,"uid","credential.after.uid")],
  ["이전 실행 권한 EUID",id(before,"euid","credential.before.euid")],["이후 실행 권한 EUID",id(after,"euid","credential.after.euid")],
  ["이전 saved UID",id(before,"suid","credential.before.suid")],["이후 saved UID",id(after,"suid","credential.after.suid")],
  ["이전 user namespace",privilegeAvailable(event,"credential.before.user_namespace")?privilegeNamespace(before.user_namespace):"미확인"],
  ["이후 user namespace",privilegeAvailable(event,"credential.after.user_namespace")?privilegeNamespace(after.user_namespace):"미확인"],
  ["namespace 해석","초기 user namespace도 컨테이너의 다른 격리·Capability 제한이 없거나 탈출했다는 증거는 아닙니다."],
  ["이전 effective Capability",cap(before,"effective","credential.before.capabilities")],["이후 effective Capability",cap(after,"effective","credential.after.capabilities")],
  ["이전 permitted Capability",cap(before,"permitted","credential.before.capabilities")],["이후 permitted Capability",cap(after,"permitted","credential.after.capabilities")],
 ];
 const beforeCaps=privilegeObject(before.capabilities),afterCaps=privilegeObject(after.capabilities),be=privilegeCapabilitySet(beforeCaps.effective),bp=privilegeCapabilitySet(beforeCaps.permitted),ae=privilegeCapabilitySet(afterCaps.effective),ap=privilegeCapabilitySet(afterCaps.permitted);
 if(applied&&be!==null&&bp!==null&&ae!==null&&ap!==null){
  const addedEffective=ae.filter(name=>!be.includes(name)),activated=addedEffective.filter(name=>bp.includes(name)),newAuthority=[...new Set([...ap.filter(name=>!bp.includes(name)),...addedEffective.filter(name=>!bp.includes(name))])];
  fields.push(["새 권한집합 증가",newAuthority.length?newAuthority.join(" · "):"관측된 증가 없음"],["기존 permitted 권한 활성화",activated.length?activated.join(" · "):"관측된 활성화 없음"]);
 }else fields.push(["Capability 변화 판정","미확인 · 이전 자료가 없거나 적용 증거가 불충분하면 새 권한 획득으로 추정하지 않습니다."]);
 fields.push(["관측 프로세스 TGID",privilegeTaskID(value.tgid)],["관측 스레드 TID",privilegeTaskID(value.tid)],["태스크 시작값(ns)",privilegeTaskStart(value.task_start_time_ns)],["증거 종류",fixed?"고정 commit_creds 전·후/반환 관측":"검증된 종류 미확인"],["관측 함수",fixed?"commit_creds":"미확인"],["원래 반환값",Number.isSafeInteger(value.return_value)?String(value.return_value):"미수집"]);
 return {summary,fields};
}
function privilegeProcessFields(event){
 const process=privilegeObject(event.process),snapshot=privilegeObject(process.credentials);
 if(!process.credentials&&!process.exec_privileges)return [];
 const available=path=>privilegeAvailable(event,path);
 const fields=[["자격 증명 시점","실행 시점 스냅샷입니다. 현재 프로세스 권한이나 권한 변경 전후를 증명하지 않습니다."],
 ["실행 스냅샷 user namespace",available("process.credentials.user_namespace")?privilegeNamespace(snapshot.user_namespace):"미확인"],
 ["실행 스냅샷 saved UID",available("process.credentials.suid")?privilegeID(snapshot.suid):"미수집"],
 ["실행 스냅샷 effective Capability",available("process.credentials.capabilities")?privilegeCapabilitiesText(privilegeObject(snapshot.capabilities).effective):"미수집"]];
 const properties=privilegeObject(process.exec_privileges);
 if(available("process.exec_privileges")){
  if(properties.setuid!==undefined)fields.push(["실행 파일 SUID 메타데이터",privilegeID(properties.setuid)]);
  if(properties.setgid!==undefined)fields.push(["실행 파일 SGID 메타데이터",privilegeID(properties.setgid)]);
  const reasons={PRIVILEGES_RAISED_EXEC_FILE_CAP:"파일 Capability에 따른 실행 권한 메타데이터",PRIVILEGES_RAISED_EXEC_FILE_SETUID:"SUID에 따른 실행 권한 메타데이터",PRIVILEGES_RAISED_EXEC_FILE_SETGID:"SGID에 따른 실행 권한 메타데이터"};
  if(Array.isArray(properties.reasons)&&properties.reasons.length){
    const reviewed=properties.reasons.length<=3&&properties.reasons.every(reason=>typeof reason==="string"&&Object.hasOwn(reasons,reason));
    fields.push(["실행 권한 메타데이터",reviewed?properties.reasons.map(reason=>reasons[reason]).join(" · "):"검토된 사유 미확인"]);
  }
 }
 return fields;
}
