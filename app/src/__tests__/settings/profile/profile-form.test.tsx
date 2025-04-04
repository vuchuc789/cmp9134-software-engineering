import ProfilePage from '@/app/settings/profile/page';
import '@testing-library/jest-dom';
import { render } from '@testing-library/react';
import { act } from 'react';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ replace: () => {} }),
}));

jest.mock('../../../contexts/auth', () => ({
  useAuth: jest.fn(() => ({ state: { accessToken: 'abc', isLoading: false } })),
}));

describe('ProfilePage', () => {
  it('renders profile page unchanged', async () => {
    let container;
    await act(async () => {
      const result = render(<ProfilePage />);

      container = result.container;
    });

    expect(container).toMatchSnapshot();
  });
});
