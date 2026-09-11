const STRINGS={
  en:{nav_home:'Command center',nav_runbooks:'Runbooks',nav_templates:'Templates',nav_analytics:'Analytics',nav_admin:'Administration',login_button:'Sign in',action_start:'▶ Start',action_complete:'✓ Complete',action_skipped:'skipped'},
  ja:{nav_home:'コマンドセンター',nav_runbooks:'ランブック',nav_templates:'テンプレート',nav_analytics:'分析',nav_admin:'管理',login_button:'サインイン',action_start:'▶ 開始',action_complete:'✓ 完了',action_skipped:'スキップ'},
};
function currentLocale(){const loc=localStorage.getItem('flowops_locale');return STRINGS[loc]?loc:'en'}
function t(key){const loc=currentLocale();return (STRINGS[loc]&&STRINGS[loc][key])||STRINGS.en[key]||key}
function setLocale(loc){localStorage.setItem('flowops_locale',STRINGS[loc]?loc:'en');applyLocale()}
function applyLocale(){
  const navMap={home:'nav_home',runbooks:'nav_runbooks',templates:'nav_templates',analytics:'nav_analytics',admin:'nav_admin'};
  document.querySelectorAll('.nav[data-view]').forEach(btn=>{
    const key=navMap[btn.dataset.view];
    if(key){const span=btn.querySelector('span');if(span)span.textContent=t(key)}
  });
  const loginBtn=document.querySelector('.login-button');
  if(loginBtn)loginBtn.textContent=t('login_button');
}
if(typeof document!=='undefined')document.addEventListener('DOMContentLoaded',applyLocale);
