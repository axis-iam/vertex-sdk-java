import { createRoot } from 'react-dom/client';
import { useState } from 'react';
import { ConnectedAppSessionTransport } from '@axis-iam/vertex';
import { IamProvider, SignIn, AuthDialog, ForgotPassword, useAuth, useAuthFlow, useServerSession } from '@axis-iam/vertex-react';

function Headless() {
  const {state, actions}=useAuthFlow();
  const [identifier,setIdentifier]=useState('');
  const [password,setPassword]=useState('');
  const [code,setCode]=useState('');
  return <section aria-label="Headless login"><p>Step: {state.step}</p>
    {state.step==='identifier' && <form onSubmit={event=>{event.preventDefault();actions.continueWithIdentifier({kind:'EMAIL',value:identifier});}}>
      <label>Email<input aria-label="Headless email" type="email" required value={identifier} onChange={e=>setIdentifier(e.target.value)}/></label><button>Continue</button></form>}
    {state.step==='method' && <form onSubmit={event=>{event.preventDefault();actions.continueWithIdentifier({kind:'EMAIL',value:identifier});void actions.submitPassword(password);}}>
      <label>Email<input aria-label="Headless email" type="email" required value={identifier} onChange={e=>setIdentifier(e.target.value)}/></label>
      <label>Password<input aria-label="Headless password" type="password" required value={password} onChange={e=>setPassword(e.target.value)}/></label><button>Sign in</button></form>}
    {state.step==='method' && <><button onClick={()=>{actions.continueWithIdentifier({kind:'EMAIL',value:identifier});actions.selectMethod('magic_link');void actions.sendMagicLink();}}>Send magic link</button>
      <button onClick={()=>void actions.completeMagicLink(location.href)}>Complete email link</button></>}
    {state.step==='mfa' && <form onSubmit={event=>{event.preventDefault();void actions.verifyMfa(code,'TOTP');}}>
      <label>Code<input aria-label="Headless MFA code" value={code} onChange={e=>setCode(e.target.value)}/></label><button>Verify</button></form>}
    {state.error && <p role="alert">{state.error.message}</p>}
  </section>;
}
function Application() {
  const {isLoaded,isAuthenticated,user,login,logout,initializationError}=useAuth();
  const [dialog,setDialog]=useState(true), [business,setBusiness]=useState(''),[operationError,setOperationError]=useState('');
  async function signOut(){try{await logout({redirect:false});setOperationError('');}catch{setOperationError('Sign out could not be confirmed. Reload to check the session.');}}
  const {view,actions:sessionActions}=useServerSession();
  async function switchEntry(event,next){event.preventDefault();try{
    if(view && view.state!=='PRELOGIN' && !('profile' in view)) await sessionActions.request({action:'cancel'});
    location.assign(`/?entry=${next}`);
  }catch{setOperationError('Cancel the current attempt before changing entry.');}}
  const [entry]=useState(()=>new URLSearchParams(location.search).get('entry') ?? 'embedded');
  return <main><h1>Axis Vertex Java BFF</h1>
    {operationError && <p role="alert">{operationError}</p>}
    <nav>{['hosted','embedded','dialog','headless'].map(name=><a key={name} href={`/?entry=${name}`} onClick={event=>void switchEntry(event,name)} style={{marginRight:'1rem'}}>{name[0].toUpperCase()+name.slice(1)}</a>)}</nav>
    {!isLoaded ? <p>Loading session</p> : initializationError ? <p role="alert">{initializationError.message}</p> : isAuthenticated ? <section>
      <p data-testid="signed-in">Signed in: {user.email ?? user.id}</p><p>Browser token: none</p>
      <button onClick={async()=>{const response=await fetch('/api/documents',{credentials:'same-origin'});setBusiness(String(response.status));}}>Read documents</button>
      <output aria-label="Business response">{business}</output><button onClick={()=>void signOut()}>Sign out</button>
    </section> : <>{entry==='hosted' && <button onClick={()=>void login()}>Hosted sign in</button>}
      {entry==='hosted' ? null : entry==='forgot' ? <ForgotPassword/> : entry==='headless' ? <Headless/> : entry==='dialog' ? <AuthDialog open={dialog} onOpenChange={setDialog} mode="embedded" allowSignUp signInProps={{providerNavigation:'redirect'}}/> : <SignIn mode="embedded" allowSignUp providerNavigation="redirect" forgotPasswordUrl="/?entry=forgot"/>}
    </>}
  </main>;
}
const response=await fetch('/web-config',{cache:'no-store'});
if(!response.ok) throw new Error('Public application configuration unavailable');
const config=await response.json();
const transport=new ConnectedAppSessionTransport({origin:location.origin,basePath:'/auth'});
createRoot(document.getElementById('root')).render(<IamProvider {...config} sessionMode="server_session" sessionTransport={transport}
 sessionLoginUri={`${location.origin}/auth/login`} sessionProviderReturnUri={`${location.origin}/`} sessionMagicReturnUri={`${location.origin}/`} locale="en"><Application/></IamProvider>);
