import { chromium } from 'playwright';
import { readFile, writeFile } from 'node:fs/promises';
import { parseServerSession } from '@axis-iam/vertex';
import assert from 'node:assert/strict';
const runtime=JSON.parse(await readFile(process.argv[2],'utf8'));
const vectors=JSON.parse(await readFile('../src/test/resources/connected-app-bff/c0-v1.json','utf8'));
for(const vector of vectors.viewVectors){
  let accepted=true;try{parseServerSession(vector.value);}catch{accepted=false;}
  assert.equal(accepted,vector.accept,vector.id);
}
const browser=await chromium.launch({executablePath:process.env.BFF_CHROME_PATH??'/bin/google-chrome',headless:true,args:['--no-sandbox']});
const results=[];
const tokenRequests=[];
browser.on('context',context=>context.on('request',request=>{if(new URL(request.url()).pathname==='/oauth2/token')tokenRequests.push('browser-token-request');}));
function record(result){results.push(result);console.log(JSON.stringify(result));}
let page;
async function signedIn(){await page.getByTestId('signed-in').waitFor();await page.getByRole('button',{name:'Read documents',exact:true}).click();
 await page.getByLabel('Business response').filter({hasText:'200'}).waitFor();
 const safe=await page.evaluate(async()=>({session:await(await fetch('/auth/session')).json(),dom:document.body.innerText,url:location.href,
   cookie:window.document['cookie'],local:{...localStorage},sessionStorage:{...sessionStorage}}));
 assert.equal(safe.session.state,'AUTHENTICATED');assert.ok(!new URL(safe.url).hash);for(const key of ['code','state','kind','auth_transaction_id']) assert.ok(!new URL(safe.url).searchParams.has(key));
 assert.match(safe.dom,/Browser token: none/);
 const serialized=JSON.stringify(safe);for(const marker of ['fixture-access','fixture-refresh','fixture-control','fixture-secret','fixture-code','fixture-magic-proof','code_verifier']) assert.ok(!serialized.includes(marker),marker);
 return safe;
}
async function mfa(){await page.getByRole('button',{name:/verify/i}).waitFor();
 await page.locator('input:not([type="password"]):not([type="hidden"])').last().fill('123456');
 await page.getByRole('button',{name:/verify/i}).click();}
async function password(entry){
 await page.goto(`${runtime.origin}/?entry=${entry}`); await page.getByRole('textbox').first().fill('reader@example.test');
 if(await page.getByRole('button',{name:'Continue',exact:true}).count()) await page.getByRole('button',{name:'Continue',exact:true}).click();
 await page.locator('input[type="password"]').fill('fixture-password');await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await mfa();await signedIn();
}
try{
 for(const entry of ['embedded','dialog','headless']){
  const context=await browser.newContext();page=await context.newPage();
  page.on('pageerror',error=>console.error('Browser error:',error.message));
  await password(entry);await page.screenshot({path:`${entry}-authenticated.png`,fullPage:true});
  await page.reload();await signedIn();
  await page.getByRole('button',{name:'Sign out',exact:true}).click();await page.getByTestId('signed-in').waitFor({state:'detached'});
  record({scenario:`${entry}-password-mfa-reload-business-logout`,result:'PASS'});await context.close();
 }
 {
  const context=await browser.newContext();page=await context.newPage();await page.goto(runtime.origin+'/?entry=hosted');
  await page.getByRole('button',{name:'Hosted sign in',exact:true}).click();await page.getByRole('link',{name:'Complete Hosted login',exact:true}).click();
  await signedIn();record({scenario:'hosted-top-level-navigation',result:'PASS'});await context.close();
 }
 {
  const context=await browser.newContext();page=await context.newPage();await page.goto(runtime.origin);
  await page.getByRole('button',{name:/Fixture Provider/}).click();await page.getByRole('link',{name:'Continue with MFA',exact:true}).click();
  await mfa();await signedIn();record({scenario:'provider-continuation-mfa',result:'PASS'});await context.close();
 }
 {
  const context=await browser.newContext();page=await context.newPage();await page.goto(runtime.origin);
  await page.getByRole('button',{name:/Fixture Provider/}).click();await page.getByRole('link',{name:'Complete provider login',exact:true}).click();
  await signedIn();record({scenario:'provider-code-consumed-by-java',result:'PASS'});await context.close();
 }
 {
  const context=await browser.newContext();page=await context.newPage();await page.goto(runtime.origin);
  await page.getByRole('button',{name:/Fixture Provider/}).click();await page.getByRole('link',{name:'Deny provider',exact:true}).click();
  await page.getByRole('textbox').first().waitFor();
  assert.equal((await page.request.get(runtime.origin+'/api/documents')).status(),401);
  record({scenario:'provider-denial-recovers-anonymous',result:'PASS'});await context.close();
 }
 {
  const context=await browser.newContext();page=await context.newPage();await page.goto(runtime.origin+'/?entry=headless');
  await page.getByLabel('Headless email').fill('reader@example.test');
  if(await page.getByRole('button',{name:'Continue',exact:true}).count()) await page.getByRole('button',{name:'Continue',exact:true}).click();
  await page.getByRole('button',{name:'Send magic link',exact:true}).click();
  const magic=await(await fetch(runtime.iam+'/fixture/magic')).json();
  await page.evaluate(url=>history.replaceState(null,'',url),magic.url);
  await page.getByRole('button',{name:'Complete email link',exact:true}).click();await mfa();await signedIn();
  record({scenario:'email-fragment-cleanup-bound-magic-mfa',result:'PASS'});await context.close();
 }
 assert.equal(tokenRequests.length,0);
 await writeFile('browser-results.json',JSON.stringify({browserVersion:browser.version(),c0Vectors:vectors.viewVectors.length,results},null,2)+'\n');
 console.log(JSON.stringify({browserVersion:browser.version(),results}));
}catch(error){
 if(page){console.error('Browser URL:',page.url());console.error((await page.locator('body').innerText()).slice(0,6000));await page.screenshot({path:'browser-failure.png',fullPage:true});}
 throw error;
}finally{await browser.close();}
