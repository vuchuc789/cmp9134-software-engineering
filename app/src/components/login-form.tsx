'use client';

import { loginForAccessTokenUsersLoginPost } from '@/client';
import { zBodyLoginForAccessTokenUsersLoginPost } from '@/client/zod.gen';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import { zodResolver } from '@hookform/resolvers/zod';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';
import { z } from 'zod';
import {
  Form,
  FormControl,
  FormField,
  FormLabel,
  FormMessage,
} from './ui/form';

export function LoginForm({
  className,
  ...props
}: React.ComponentProps<'div'>) {
  const form = useForm<z.infer<typeof zBodyLoginForAccessTokenUsersLoginPost>>({
    resolver: zodResolver(zBodyLoginForAccessTokenUsersLoginPost),
    defaultValues: {
      grant_type: 'password',
      username: '',
      password: '',
    },
  });

  const router = useRouter();

  const onSubmit = async (
    values: z.infer<typeof zBodyLoginForAccessTokenUsersLoginPost>
  ) => {
    if (!values.username || !values.password) {
      toast.error('Username and password should not be empty');
      return;
    }

    const res = await loginForAccessTokenUsersLoginPost({
      body: values,
    });

    if (res.response.status === 200) {
      toast.success('Logged in successfully');
      router.push('/');
    } else if (res.response.status >= 400) {
      if (typeof res.error?.detail === 'string') {
        toast.error(res.error.detail);
      } else {
        toast.error('Something went wrong');
      }
    }
  };

  return (
    <div className={cn('flex flex-col gap-6', className)} {...props}>
      <Card>
        <CardHeader>
          <CardTitle>Login to your account</CardTitle>
          <CardDescription>
            Enter your username below to login to your account
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)}>
              <div className="flex flex-col gap-6">
                <FormField
                  control={form.control}
                  name="username"
                  render={({ field }) => (
                    <div className="grid gap-3">
                      <FormLabel htmlFor="username">Username</FormLabel>
                      <FormControl>
                        <Input
                          id="username"
                          placeholder="johndoe"
                          type="text"
                          autoComplete="username"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </div>
                  )}
                />
                <FormField
                  control={form.control}
                  name="password"
                  render={({ field }) => (
                    <div className="grid gap-3">
                      {/* <div className="flex items-center"> */}
                      <FormLabel htmlFor="password">Password</FormLabel>
                      {/* <a
                          href="#"
                          className="ml-auto inline-block text-sm underline-offset-4 hover:underline"
                        >
                          Forgot your password?
                        </a> */}
                      {/* </div> */}
                      <FormControl>
                        <Input
                          id="password"
                          type="password"
                          autoComplete="current-password"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </div>
                  )}
                />

                {/* <div className="flex flex-col gap-3"> */}
                <Button type="submit" className="w-full">
                  Login
                </Button>
                {/* <Button variant="outline" className="w-full">
                  Login with Google
                </Button> */}
                {/* </div> */}
              </div>
              <div className="mt-4 text-center text-sm">
                Don&apos;t have an account?{' '}
                <Link href="/signup" className="underline underline-offset-4">
                  Sign up
                </Link>
              </div>
            </form>
          </Form>
        </CardContent>
      </Card>
    </div>
  );
}
