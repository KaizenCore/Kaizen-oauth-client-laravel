<?php

namespace Kaizen\OAuth;

use Laravel\Socialite\Two\User;

class KaizenUser extends User
{
    /**
     * Get the Minecraft UUID.
     */
    public function getMinecraftUuid(): ?string
    {
        return $this->attributes['minecraft_uuid'] ?? null;
    }

    /**
     * Get the Minecraft username.
     */
    public function getMinecraftUsername(): ?string
    {
        return $this->attributes['minecraft_username'] ?? null;
    }

    /**
     * Check if the user has a linked Minecraft account.
     */
    public function hasMinecraftAccount(): bool
    {
        return ! empty($this->getMinecraftUuid());
    }

    /**
     * Get a specific attribute from the raw user data.
     */
    public function getAttribute(string $key, mixed $default = null): mixed
    {
        return $this->user[$key] ?? $default;
    }

    /**
     * Get all raw attributes.
     */
    public function getAttributes(): array
    {
        return $this->user;
    }

    /**
     * Check if the user has a specific role.
     *
     * Supports both "role" (string) and "roles" (array) formats.
     */
    public function hasRole(string $role): bool
    {
        // Check "role" as string
        $userRole = $this->getAttribute('role');
        if ($userRole === $role) {
            return true;
        }

        // Check "roles" as array
        $roles = $this->getAttribute('roles', []);

        return is_array($roles) && in_array($role, $roles);
    }

    /**
     * Check if the user is an admin.
     *
     * Supports both "role" (string) and "roles" (array) formats.
     */
    public function isAdmin(): bool
    {
        // Check "role" as string first
        if ($this->getAttribute('role') === 'admin') {
            return true;
        }

        return $this->hasRole('admin');
    }

    /**
     * Get the user's locale preference.
     */
    public function getLocale(): string
    {
        return $this->getAttribute('locale', 'en');
    }
}
