#if !UNITY_WEBGL || UNITY_EDITOR
using System;

namespace Nucleus.Integrations.Unity.Transports
{
    /// <summary>
    /// Marks a static method native code calls back into, which IL2CPP needs to generate the entry point for.
    /// </summary>
    /// <remarks>IL2CPP recognises the attribute by its name in any namespace, so this one serves outside Unity as well as inside it.</remarks>
    [AttributeUsage(AttributeTargets.Method)]
    internal sealed class MonoPInvokeCallbackAttribute : Attribute
    {
        /// <summary>
        /// Creates a new instance.
        /// </summary>
        /// <param name="delegateType">The delegate type native code calls the method through.</param>
        public MonoPInvokeCallbackAttribute(Type delegateType) { }
    }
}
#endif
