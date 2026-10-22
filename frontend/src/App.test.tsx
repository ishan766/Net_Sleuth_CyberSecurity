// @vitest-environment jsdom
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen} from '@testing-library/react';
import App from './App';

afterEach(()=>{cleanup();vi.unstubAllGlobals()});

it('shows an honest empty investigation and opens import',async()=>{
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue({ok:true,json:async()=>[]}));
  render(<App/>);
  expect(await screen.findByText('No capture selected')).toBeTruthy();
  fireEvent.click(screen.getAllByText('Import capture')[0]);
  expect(await screen.findByText('Select a PCAP or PCAPNG file')).toBeTruthy();
});

it('shows a failed sample import to the user',async()=>{
  vi.stubGlobal('fetch',vi.fn().mockImplementation(async(url:string)=>url.endsWith('/sample')?{ok:false,json:async()=>({detail:'Sample capture is missing'})}:{ok:true,json:async()=>[]}));
  render(<App/>);
  fireEvent.click(await screen.findByRole('button',{name:'Import a capture'}));
  fireEvent.click(screen.getByRole('button',{name:'Load sample capture'}));
  expect(await screen.findByRole('alert')).toHaveProperty('textContent','Sample capture is missing');
});
