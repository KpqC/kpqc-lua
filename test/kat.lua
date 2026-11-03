local kpqc = require("kpqc")

local vector_root = os.getenv("KPQC_TEST_VECTORS")
assert(vector_root and vector_root ~= "", "KPQC_TEST_VECTORS is not set")
assert(type(kpqc._aes256_ecb) == "function", "KATs require KPQC_TEST_ENTROPY=ON")

local function join_path(...)
   return table.concat({ ... }, "/")
end

local function hex_to_bytes(value)
   assert(#value % 2 == 0, "hex value has an odd length")
   local bytes = {}
   for index = 1, #value, 2 do
      bytes[#bytes + 1] = string.char(tonumber(string.sub(value, index, index + 1), 16))
   end
   return table.concat(bytes)
end

local function read_vectors(path)
   local file = assert(io.open(path, "r"))
   local vectors = {}
   local current = {}
   for line in file:lines() do
      local name, value = string.match(line, "^([^=]+) = (.*)$")
      if name then
         name = string.gsub(name, "%s+$", "")
         if name == "count" and next(current) ~= nil then
            vectors[#vectors + 1] = current
            current = {}
         end
         current[name] = value
      end
   end
   file:close()
   if next(current) ~= nil then
      vectors[#vectors + 1] = current
   end
   return vectors
end

local function field(vector, name)
   assert(vector[name], "missing vector field: " .. name)
   return hex_to_bytes(vector[name])
end

local function byte_xor(left, right)
   local result = 0
   local place = 1
   while left > 0 or right > 0 do
      local left_bit = left % 2
      local right_bit = right % 2
      if left_bit ~= right_bit then
         result = result + place
      end
      left = math.floor(left / 2)
      right = math.floor(right / 2)
      place = place * 2
   end
   return result
end

local function xor_strings(left, right)
   assert(#left == #right)
   local result = {}
   for index = 1, #left do
      result[index] = string.char(byte_xor(
         string.byte(left, index),
         string.byte(right, index)
      ))
   end
   return table.concat(result)
end

local function increment_counter(counter)
   local bytes = { string.byte(counter, 1, #counter) }
   for index = #bytes, 1, -1 do
      bytes[index] = (bytes[index] + 1) % 256
      if bytes[index] ~= 0 then
         break
      end
   end
   local result = {}
   for index = 1, #bytes do
      result[index] = string.char(bytes[index])
   end
   return table.concat(result)
end

local function generate_blocks(state, count)
   local output = {}
   for index = 1, count do
      state.counter = increment_counter(state.counter)
      output[index] = kpqc._aes256_ecb(state.key, state.counter)
   end
   return table.concat(output)
end

local function update(state, provided)
   assert(#provided <= 48, "DRBG update data must not exceed 48 bytes")
   local material = generate_blocks(state, 3)
   local padded = provided .. string.rep("\0", 48 - #provided)
   material = xor_strings(material, padded)
   state.key = string.sub(material, 1, 32)
   state.counter = string.sub(material, 33, 48)
end

local function new_drbg(seed)
   assert(#seed == 48, "CTR-DRBG seed must contain 48 bytes")
   local state = {
      key = string.rep("\0", 32),
      counter = string.rep("\0", 16)
   }
   update(state, seed)
   return state
end

local function copy_drbg(state)
   return { key = state.key, counter = state.counter }
end

local function generate(state, length)
   local blocks = math.floor((length + 15) / 16)
   local output = generate_blocks(state, blocks)
   update(state, "")
   return string.sub(output, 1, length)
end

local function with_exact_entropy(algorithm, entropy, operation)
   algorithm._set_test_entropy(entropy)
   local result = { pcall(operation) }
   local remaining = algorithm._test_entropy_remaining()
   algorithm._clear_test_entropy()
   if not result[1] then
      error(result[2], 0)
   end
   assert(remaining == 0, "deterministic entropy has " .. remaining .. " unused bytes")
   return result[2]
end

local function with_repeated_entropy(algorithm, state, call_bytes, operation)
   local probe = copy_drbg(state)
   local chunks = {}
   for index = 1, 128 do
      chunks[index] = generate(probe, call_bytes)
   end
   local entropy = table.concat(chunks)

   algorithm._set_test_entropy(entropy)
   local result = { pcall(operation) }
   local consumed = #entropy - algorithm._test_entropy_remaining()
   algorithm._clear_test_entropy()
   if not result[1] then
      error(result[2], 0)
   end
   assert(consumed > 0, "deterministic entropy was not consumed")
   assert(consumed % call_bytes == 0, "entropy consumption was not aligned")
   for _ = 1, consumed / call_bytes do
      generate(state, call_bytes)
   end
   return result[2]
end

local signatures = {
   { kpqc.aimer128f, "aimer/128f", false, 16 },
   { kpqc.aimer128s, "aimer/128s", false, 16 },
   { kpqc.aimer192f, "aimer/192f", false, 24 },
   { kpqc.aimer192s, "aimer/192s", false, 24 },
   { kpqc.aimer256f, "aimer/256f", false, 32 },
   { kpqc.aimer256s, "aimer/256s", false, 32 },
   { kpqc.haetae2, "haetae/mode2", true, 32 },
   { kpqc.haetae3, "haetae/mode3", true, 32 },
   { kpqc.haetae5, "haetae/mode5", true, 32 }
}

local kems = {
   { kpqc.ntruplus768, "ntruplus/768", 0, 96 },
   { kpqc.ntruplus864, "ntruplus/864", 0, 108 },
   { kpqc.ntruplus1152, "ntruplus/1152", 0, 144 },
   { kpqc.smaugt128, "smaugt/mode1", 2, 32 },
   { kpqc.smaugt192, "smaugt/mode3", 2, 32 },
   { kpqc.smaugt256, "smaugt/mode5", 2, 32 },
   { kpqc.timer, "smaugt/modet", 2, 16 }
}

local total = 0

for _, configuration in ipairs(signatures) do
   local algorithm, path, is_haetae, seed_bytes =
      configuration[1], configuration[2], configuration[3], configuration[4]
   local vectors = read_vectors(join_path(vector_root, path, "kat.rsp"))
   assert(#vectors == 100, path .. " must contain 100 vectors")

   for _, vector in ipairs(vectors) do
      local state = new_drbg(field(vector, "seed"))
      local keys
      if is_haetae then
         keys = with_exact_entropy(
            algorithm,
            generate(state, seed_bytes),
            algorithm.generate_keypair
         )
      else
         keys = with_repeated_entropy(
            algorithm,
            state,
            seed_bytes,
            algorithm.generate_keypair
         )
      end
      assert(keys.public_key == field(vector, "pk"), path .. " public key mismatch")
      assert(keys.secret_key == field(vector, "sk"), path .. " secret key mismatch")

      local message = field(vector, "msg")
      local expected_signature
      if vector.sig then
         expected_signature = field(vector, "sig")
      else
         expected_signature = string.sub(field(vector, "sm"), #message + 1)
      end
      local signing_entropy = generate(state, seed_bytes)
      local context = ""
      if is_haetae then
         local context_length = string.byte(generate(state, 1))
         context = generate(state, context_length)
      end
      local signature = with_exact_entropy(
         algorithm,
         signing_entropy,
         function()
            return algorithm.sign(message, keys.secret_key, context)
         end
      )
      assert(signature == expected_signature, path .. " signature mismatch")
      assert(
         algorithm.verify(message, expected_signature, keys.public_key, context),
         path .. " signature verification failed"
      )
   end

   total = total + #vectors
   print("KAT passed: " .. path)
end

for _, configuration in ipairs(kems) do
   local algorithm, path, key_calls, encapsulation_bytes =
      configuration[1], configuration[2], configuration[3], configuration[4]
   local vectors = read_vectors(join_path(vector_root, path, "kat.rsp"))
   assert(#vectors == 100, path .. " must contain 100 vectors")

   for _, vector in ipairs(vectors) do
      local state = new_drbg(field(vector, "seed"))
      local keys
      if key_calls == 0 then
         keys = with_repeated_entropy(
            algorithm,
            state,
            32,
            algorithm.generate_keypair
         )
      else
         local entropy = {}
         for index = 1, key_calls do
            entropy[index] = generate(state, 32)
         end
         keys = with_exact_entropy(
            algorithm,
            table.concat(entropy),
            algorithm.generate_keypair
         )
      end
      assert(keys.public_key == field(vector, "pk"), path .. " public key mismatch")
      assert(keys.secret_key == field(vector, "sk"), path .. " secret key mismatch")

      local outbound = with_exact_entropy(
         algorithm,
         generate(state, encapsulation_bytes),
         function()
            return algorithm.encapsulate(keys.public_key)
         end
      )
      assert(outbound.ciphertext == field(vector, "ct"), path .. " ciphertext mismatch")
      assert(outbound.shared_secret == field(vector, "ss"), path .. " shared secret mismatch")
      assert(
         algorithm.decapsulate(outbound.ciphertext, keys.secret_key)
            == outbound.shared_secret,
         path .. " decapsulation mismatch"
      )
   end

   total = total + #vectors
   print("KAT passed: " .. path)
end

assert(total == 1600, "expected 1,600 vectors, received " .. total)
print("All 1,600 known-answer records passed")
