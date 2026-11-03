local kpqc = require("kpqc")

local message = "release-manifest:v3"
local context = "kpqc-lua"

local function expect_error(operation)
   local ok = pcall(operation)
   assert(not ok, "operation should have raised an error")
end

local function tamper(value)
   assert(#value > 0)
   local first = string.char((string.byte(value, 1) + 1) % 256)
   return first .. string.sub(value, 2)
end

assert(kpqc._VERSION == "0.1.0")
assert(#kpqc.signature_algorithms == 9)
assert(#kpqc.kem_algorithms == 7)
assert(kpqc.aimer128f.id == "aimer-128f")
assert(kpqc.aimer128f.type == "signature")
assert(kpqc.ntruplus768.id == "NTRU+768")
assert(kpqc.ntruplus768.type == "kem")
assert(kpqc.haetae5.sizes.public_key == 2080)
assert(kpqc.haetae5.sizes.secret_key == 2752)
assert(kpqc.haetae5.sizes.signature == 2948)
assert(kpqc.timer.sizes.public_key == 672)
assert(kpqc.timer.sizes.secret_key == 832)
assert(kpqc.timer.sizes.ciphertext == 608)
assert(kpqc.timer.sizes.shared_secret == 32)
assert(kpqc._aes256_ecb == nil)

for _, algorithm in ipairs(kpqc.signature_algorithms) do
   local keys = algorithm.generate_keypair()
   assert(#keys.public_key == algorithm.sizes.public_key)
   assert(#keys.secret_key == algorithm.sizes.secret_key)

   local signature = algorithm.sign(message, keys.secret_key, context)
   assert(#signature == algorithm.sizes.signature)
   assert(algorithm.verify(message, signature, keys.public_key, context))
   assert(not algorithm.verify(message, signature, keys.public_key))
   assert(not algorithm.verify(
      message,
      tamper(signature),
      keys.public_key,
      context
   ))
   assert(not algorithm.verify(message, "", keys.public_key, context))
end

do
   local algorithm = kpqc.aimer128f
   local keys = algorithm.generate_keypair()
   expect_error(function()
      algorithm.sign(message, "")
   end)
   expect_error(function()
      algorithm.sign(123, keys.secret_key)
   end)
   expect_error(function()
      algorithm.verify(message, string.rep("\0", algorithm.sizes.signature), "")
   end)
   expect_error(function()
      algorithm.sign(message, keys.secret_key, string.rep("x", 256))
   end)

   local empty_signature = algorithm.sign("", keys.secret_key)
   assert(algorithm.verify("", empty_signature, keys.public_key))

   local maximum_context = string.rep("x", 255)
   local signature = algorithm.sign(message, keys.secret_key, maximum_context)
   assert(algorithm.verify(message, signature, keys.public_key, maximum_context))
end

for _, algorithm in ipairs(kpqc.kem_algorithms) do
   local keys = algorithm.generate_keypair()
   assert(#keys.public_key == algorithm.sizes.public_key)
   assert(#keys.secret_key == algorithm.sizes.secret_key)

   local outbound = algorithm.encapsulate(keys.public_key)
   assert(#outbound.ciphertext == algorithm.sizes.ciphertext)
   assert(#outbound.shared_secret == algorithm.sizes.shared_secret)
   assert(
      algorithm.decapsulate(outbound.ciphertext, keys.secret_key)
         == outbound.shared_secret
   )
end

do
   local algorithm = kpqc.ntruplus768
   local keys = algorithm.generate_keypair()
   expect_error(function()
      algorithm.encapsulate("")
   end)
   expect_error(function()
      algorithm.decapsulate("", keys.secret_key)
   end)
   expect_error(function()
      algorithm.decapsulate(
         string.rep("\0", algorithm.sizes.ciphertext),
         ""
      )
   end)
end

for _, algorithm in ipairs({
   kpqc.ntruplus768,
   kpqc.ntruplus864,
   kpqc.ntruplus1152
}) do
   local keys = algorithm.generate_keypair()
   local outbound = algorithm.encapsulate(keys.public_key)
   expect_error(function()
      algorithm.decapsulate(tamper(outbound.ciphertext), keys.secret_key)
   end)
   expect_error(function()
      algorithm.encapsulate(string.rep("\255", algorithm.sizes.public_key))
   end)
end

for _, algorithm in ipairs({
   kpqc.smaugt128,
   kpqc.smaugt192,
   kpqc.smaugt256,
   kpqc.timer
}) do
   local keys = algorithm.generate_keypair()
   local outbound = algorithm.encapsulate(keys.public_key)
   local replacement = algorithm.decapsulate(
      tamper(outbound.ciphertext),
      keys.secret_key
   )
   assert(#replacement == algorithm.sizes.shared_secret)
   assert(replacement ~= outbound.shared_secret)
end

print("API tests passed for 9 signature and 7 KEM parameter sets")
